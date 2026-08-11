"""Script to deploy and update OCI compute instances and network security configurations."""

import base64
import random
import time
from textwrap import dedent

import logfire
import oci

from common import (
    OCI_CONFIG_FILE,
    AccountSession,
    ServerConfig,
    allocate_maximum_ipv6_addresses,
    ensure_reserved_public_ip,
    get_availability_domain,
    get_latest_ubuntu_lts_image_id,
    get_or_create_ipv6_subnet,
    get_or_create_nsg,
    get_primary_private_ip_id,
    get_primary_vnic_id_with_retry,
    get_subnet_id,
    get_supported_shapes_by_ad,
    load_config,
    log_detailed_service_error,
    merge_server_rules,
    sync_instance_nsg_assignment,
    sync_nsg_security_rules,
)

INSTANCE_CREATION_SLEEP_MIN = 90
INSTANCE_CREATION_SLEEP_MAX = 150

if __name__ == "__main__":
    logfire.configure(send_to_logfire="if-token-present", scrubbing=False)

    with logfire.span("Loading config file"):
        config = load_config()

    sessions: dict[str, AccountSession] = {}
    session_supported_shapes: dict[str, dict[str, set]] = {}
    needs_work: list[tuple[str, ServerConfig]] = []

    with logfire.span("Setting up network and checking state"):
        for account_config in config.accounts:
            account_name = account_config.name
            with logfire.span(f"Configuring network and auditing {account_name}"):
                if account_name not in sessions:
                    sessions[account_name] = AccountSession.from_account(account_name, OCI_CONFIG_FILE)
                session = sessions[account_name]

                # 1. Dynamically find or configure an IPv6-enabled subnet/VCN
                subnet_id = get_or_create_ipv6_subnet(
                    session.virtual_network_client,
                    session.virtual_network_composite_operations,
                    session.compartment_id,
                )
                session.subnet_id = subnet_id

                subnet_response = session.virtual_network_client.get_subnet(subnet_id)
                if not isinstance(subnet_response, oci.response.Response):
                    raise RuntimeError("Failed to retrieve subnet details for NSG parent association.")
                vcn_id = subnet_response.data.vcn_id

                # 2. Setup and Sync isolated Network Security Groups (NSGs) for each server configuration
                for server in account_config.servers:
                    nsg_id = get_or_create_nsg(
                        session.virtual_network_client,
                        session.compartment_id,
                        vcn_id,
                        server.name,
                    )
                    session.nsg_ids[server.name] = nsg_id

                    merged_rules = merge_server_rules(server, config.defaults.security_rules)
                    sync_nsg_security_rules(session.virtual_network_client, nsg_id, merged_rules)

                # 3. Pre-flight check: Audit supported shapes across all Availability Domains (stored as logfire debug)
                supported_shapes_by_ad = get_supported_shapes_by_ad(
                    session.identity_client, session.compute_client, session.compartment_id
                )
                session_supported_shapes[account_name] = supported_shapes_by_ad
                all_supported_shapes = (
                    set().union(*supported_shapes_by_ad.values()) if supported_shapes_by_ad else set()
                )

                # 4. Determine if any instances require deployment or IPv6 self-healing
                list_instance_result = oci.pagination.list_call_get_all_results(
                    session.compute_client.list_instances, session.compartment_id
                )
                if not isinstance(list_instance_result, oci.response.Response):
                    raise RuntimeError("Failed to list active OCI instances.")

                existing_instances = {
                    i.display_name: i.id
                    for i in list_instance_result.data
                    if i.lifecycle_state not in ["TERMINATED", "TERMINATING"]
                }

                for server in account_config.servers:
                    if server.name not in existing_instances:
                        # Skip servers whose shapes are not supported in any AD for this account
                        if all_supported_shapes and server.shape not in all_supported_shapes:
                            logfire.warning(
                                f"Shape '{server.shape}' for server '{server.name}' is not supported in any "
                                f"Availability Domain on account '{account_name}'. Skipping instance creation."
                            )
                        else:
                            needs_work.append((account_name, server))
                    else:
                        instance_id = existing_instances[server.name]
                        logfire.info(
                            f"Instance '{server.name}' is already running. Auditing IPv6 and IP configuration..."
                        )
                        try:
                            vnic_id = get_primary_vnic_id_with_retry(
                                session.compute_client,
                                session.compartment_id,
                                instance_id,
                                max_retries=3,
                            )

                            allocate_maximum_ipv6_addresses(session.virtual_network_client, vnic_id)

                            nsg_id = session.nsg_ids.get(server.name)
                            if nsg_id:
                                logfire.info(
                                    f"Instance '{server.name}' is configured for NSG management. "
                                    "Auditing NSG assignment..."
                                )
                                sync_instance_nsg_assignment(
                                    session.virtual_network_client, vnic_id, nsg_id, instance_label=server.name
                                )

                            if server.reserved_ip:
                                logfire.info(
                                    f"Instance '{server.name}' is configured for reserved IPv4. Auditing mapping..."
                                )
                                private_ip_id = get_primary_private_ip_id(session.virtual_network_client, vnic_id)
                                ensure_reserved_public_ip(
                                    session.virtual_network_client,
                                    session.compartment_id,
                                    private_ip_id,
                                )
                        except Exception as e:
                            logfire.warning(f"Could not automatically audit/heal instance '{server.name}': {e}")

                pending_names = [s.name for _, s in needs_work if s.name not in existing_instances]
                logfire.info(f"Instances pending creation for {account_name}: {pending_names}")

    with logfire.span("Working on instances"):
        attempt = 1
        while len(needs_work) > 0:
            logfire.info(f"--- Attempt #{attempt} to deploy remaining instances ---")

            for account_name, server in list(needs_work):
                session = sessions[account_name]

                with logfire.span(f"Creating instance {server.name} on {account_name}"):
                    try:
                        ad = get_availability_domain(
                            session.identity_client,
                            session.compartment_id,
                            compute_client=session.compute_client,
                            shape=server.shape,
                            shapes_by_ad=session_supported_shapes.get(account_name),
                        )

                        subnet_id = session.subnet_id
                        if not subnet_id:
                            subnet_id = get_subnet_id(session.virtual_network_client, session.compartment_id)

                        image_id = get_latest_ubuntu_lts_image_id(
                            session.compute_client, session.compartment_id, server.shape
                        )

                        shape_config = None
                        if "Flex" in server.shape:
                            shape_config = oci.core.models.LaunchInstanceShapeConfigDetails(
                                ocpus=server.cpu, memory_in_gbs=server.ram
                            )

                        metadata = {"ssh_authorized_keys": server.ssh_auth_key}

                        user_data_parts = []

                        if server.swap > 0:
                            swap_block = dedent(f"""\
                                # Configure swap space
                                SWAP_PATH="/swapfile"
                                if [ ! -f "$SWAP_PATH" ]; then
                                  fallocate -l {server.swap}G "$SWAP_PATH" || \\
                                    dd if=/dev/zero of="$SWAP_PATH" bs=1M count=$(( {server.swap} * 1024 ))
                                  chmod 600 "$SWAP_PATH"
                                  mkswap "$SWAP_PATH"
                                  swapon "$SWAP_PATH"
                                  echo "$SWAP_PATH none swap sw 0 0" >> /etc/fstab
                                fi
                            """)
                            user_data_parts.append(swap_block)

                        if server.cronjobs:
                            cron_entries = "\n".join(server.cronjobs)
                            cron_block_template = dedent("""\
                                # Configure custom cronjobs
                                TMP_CRON=$(mktemp)
                                crontab -l > "$TMP_CRON" 2>/dev/null || true
                                cat << 'EOF' >> "$TMP_CRON"
                                {cron_entries}
                                EOF
                                crontab "$TMP_CRON"
                                rm -f "$TMP_CRON"
                            """)
                            cron_block = cron_block_template.format(cron_entries=cron_entries)
                            user_data_parts.append(cron_block)

                        if user_data_parts:
                            full_script = "#!/bin/bash\n" + "\n".join(user_data_parts)
                            metadata["user_data"] = base64.b64encode(full_script.encode("utf-8")).decode("utf-8")

                        nsg_id = session.nsg_ids.get(server.name)
                        nsg_ids = [nsg_id] if nsg_id else []

                        launch_details = oci.core.models.LaunchInstanceDetails(
                            compartment_id=session.compartment_id,
                            availability_domain=ad,
                            display_name=server.name,
                            shape=server.shape,
                            shape_config=shape_config,
                            create_vnic_details=oci.core.models.CreateVnicDetails(
                                subnet_id=subnet_id,
                                assign_public_ip=not server.reserved_ip,
                                assign_ipv6_ip=True,
                                nsg_ids=nsg_ids,
                            ),
                            metadata=metadata,
                            source_details=oci.core.models.InstanceSourceViaImageDetails(
                                source_type="image",
                                image_id=image_id,
                                boot_volume_size_in_gbs=server.disk,
                            ),
                        )

                        logfire.info(f"Sending request to launch {server.name} ({server.shape}) in {ad}...")
                        response = session.compute_client.launch_instance(launch_details)
                        if not isinstance(response, oci.response.Response):
                            raise RuntimeError(f"Failed to retrieve launch response payload for instance {server.name}")
                        instance = response.data
                        logfire.info(f"Launched instance {server.name}. Instance ID: {instance.id}")

                        vnic_id = get_primary_vnic_id_with_retry(
                            session.compute_client, session.compartment_id, instance.id
                        )

                        if server.reserved_ip:
                            private_ip_id = get_primary_private_ip_id(session.virtual_network_client, vnic_id)
                            ensure_reserved_public_ip(
                                session.virtual_network_client,
                                session.compartment_id,
                                private_ip_id,
                            )

                        try:
                            allocate_maximum_ipv6_addresses(session.virtual_network_client, vnic_id)
                        except Exception as e:
                            logfire.warning(f"Could not automatically bind secondary IPv6 blocks to VNIC: {e}")

                        needs_work.remove((account_name, server))

                    except oci.exceptions.ServiceError as e:
                        log_detailed_service_error(e, server.name, "launch_instance")

                        is_retryable = (
                            e.status in [429, 500, 503] or "capacity" in str(e).lower() or "limit" in str(e).lower()
                        )
                        if is_retryable:
                            logfire.warning(
                                f"Retryable error encountered for {server.name} (Status {e.status}). Retrying..."
                            )
                        else:
                            logfire.error(f"Fatal error launching {server.name}. Removing from target list.")
                            needs_work.remove((account_name, server))
                    except Exception as e:
                        logfire.error(f"Unexpected error when creating {server.name} on {account_name}: {e}. Retrying.")

                if len(needs_work) > 0:
                    sleep_time = random.randint(INSTANCE_CREATION_SLEEP_MIN, INSTANCE_CREATION_SLEEP_MAX)
                    logfire.info(f"Sleeping for {sleep_time}s before next instance...")
                    time.sleep(sleep_time)

            if len(needs_work) > 0:
                attempt += 1
                logfire.info(f"Still pending {len(needs_work)} instances. Starting next deployment pass...")

        logfire.info("Completed setup of all requested instances.")

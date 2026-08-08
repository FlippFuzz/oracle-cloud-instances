"""Script to list OCI compute instances and active Network Security Group rules."""

import logfire
import oci

from common import (
    OCI_CONFIG_FILE,
    AccountSession,
    get_instance_boot_volume_size,
    get_instance_ips_and_nsgs,
    load_config,
)


def format_security_rule(rule) -> str:
    """Convert a native OCI NSG SecurityRule model into human-readable text.

    Args:
        rule: OCI NSG SecurityRule object.

    Returns:
        Human-readable representation of the security rule.
    """
    if rule.direction == "EGRESS":
        return f"Allow Outbound traffic to {rule.destination} [Protocol: {rule.protocol}]"

    protocol_map = {
        "6": "TCP",
        "17": "UDP",
        "1": "ICMP",
        "58": "ICMPv6",
        "all": "All Protocols",
    }
    proto = protocol_map.get(rule.protocol, f"Proto {rule.protocol}")

    ports = "All Ports"
    if rule.protocol == "6" and rule.tcp_options:
        r = rule.tcp_options.destination_port_range
        if r:
            ports = f"Port {r.min}" if r.min == r.max else f"Ports {r.min}-{r.max}"
    elif rule.protocol == "17" and rule.udp_options:
        r = rule.udp_options.destination_port_range
        if r:
            ports = f"Port {r.min}" if r.min == r.max else f"Ports {r.min}-{r.max}"

    desc = f" [{rule.description}]" if rule.description else ""
    return f"Allow {proto} from {rule.source} on {ports}{desc}"


if __name__ == "__main__":
    logfire.configure(send_to_logfire="if-token-present", scrubbing=False)

    with logfire.span("Loading config"):
        config = load_config()

    sessions: dict[str, AccountSession] = {}

    for account_config in config.accounts:
        account_name = account_config.name
        with logfire.span(f"Listing instances for {account_name}"):
            try:
                if account_name not in sessions:
                    sessions[account_name] = AccountSession.from_account(account_name, OCI_CONFIG_FILE)
                session = sessions[account_name]

                # Retrieve all compartments (including subcompartments) under the tenancy
                try:
                    compartments_response = oci.pagination.list_call_get_all_results(
                        session.identity_client.list_compartments,
                        session.compartment_id,
                        compartment_id_in_subtree=True,
                    )
                    compartments = (
                        compartments_response.data if isinstance(compartments_response, oci.response.Response) else []
                    )
                except Exception as e:
                    logfire.warning(f"Could not list sub-compartments for {account_name}: {e}")
                    compartments = []

                # Build compartment ID list starting with root tenancy and mapping names
                compartment_ids = [session.compartment_id]
                compartment_names = {session.compartment_id: "Root Tenancy"}

                for comp in compartments:
                    if comp.lifecycle_state == "ACTIVE":
                        compartment_ids.append(comp.id)
                        compartment_names[comp.id] = comp.name

                # Query compute service for active instances across all active compartments
                instances = []
                for comp_id in compartment_ids:
                    try:
                        list_instances_response = oci.pagination.list_call_get_all_results(
                            session.compute_client.list_instances, comp_id
                        )
                        if isinstance(list_instances_response, oci.response.Response) and list_instances_response.data:
                            instances.extend(list_instances_response.data)
                    except Exception as e:
                        logfire.warning(f"Could not list instances in compartment {comp_id}: {e}")

                # Drop TERMINATED instances now so the emptiness check and both display loops agree
                instances = [i for i in instances if i.lifecycle_state != "TERMINATED"]

                if not instances:
                    print(f"\nAccount: {account_name}")
                    print(f"Compartment ID (Tenancy): {session.compartment_id}")
                    print("-" * 105)
                    print("No instances found.")
                else:
                    # Output the full, untruncated Compartment ID at the header level
                    print(f"\nAccount: {account_name}")
                    print(f"Compartment ID (Tenancy): {session.compartment_id}")
                    print("=" * 105)
                    print(f"{'Name':<18} | {'State':<12} | {'Shape / Specs':<22} | {'Network Addresses (IPv4 / IPv6)'}")
                    print("=" * 105)

                    for inst in instances:
                        if inst.lifecycle_state == "TERMINATED":
                            continue

                        # Extract IP addresses, bound NSG IDs, and public IP allocation type using actual compartment ID
                        ipv4s, ipv6s, _, ipv4_type = get_instance_ips_and_nsgs(
                            session.compute_client,
                            session.virtual_network_client,
                            inst.compartment_id,
                            inst.id,
                        )

                        ipv4_str = f"IPv4: {ipv4s[0]} ({ipv4_type})" if ipv4s else "IPv4: None"

                        ipv6_count = len(ipv6s)
                        ipv6_str = f"IPv6: {ipv6s[0]} ({ipv6_count} total)" if ipv6s else "IPv6: None"

                        # Fallback definitions for non-flexible micro shapes
                        static_specs = {
                            "VM.Standard.E2.1.Micro": (1, 1),
                            "VM.Standard.E3.1.Micro": (1, 1),
                            "VM.Standard.E4.1.Micro": (1, 1),
                        }

                        ocpus = "N/A"
                        ram = "N/A"
                        if inst.shape_config and inst.shape_config.ocpus:
                            ocpus = int(inst.shape_config.ocpus)
                        if inst.shape_config and inst.shape_config.memory_in_gbs:
                            ram = int(inst.shape_config.memory_in_gbs)

                        if (ocpus == "N/A" or ram == "N/A") and inst.shape in static_specs:
                            ocpus, ram = static_specs[inst.shape]

                        # Query the attached block volume sizes using actual compartment ID
                        disk_size = get_instance_boot_volume_size(
                            session.compute_client,
                            session.block_storage_client,
                            inst.compartment_id,
                            inst.id,
                            inst.availability_domain,
                        )

                        cpu_ram_disk_str = f"{ocpus}/{ram}GB/{disk_size}G"
                        comp_name = compartment_names.get(inst.compartment_id, inst.compartment_id[:15] + "...")

                        # Display Shape on Line 1, Hardware Specs and Compartment underneath, and IPv6 under IPv4
                        print(f"{inst.display_name:<18} | {inst.lifecycle_state:<12} | {inst.shape:<22} | {ipv4_str}")
                        print(f"{comp_name:<18} | {'':<12} | {cpu_ram_disk_str:<22} | {ipv6_str}")
                        print("-" * 105)
                    print("=" * 105)

                # Fetch and display the active NSG configurations for each instance
                if instances:
                    print("\n  Active Network Security Group (NSG) Rules:")
                    print("  " + "=" * 85)
                    for inst in instances:
                        if inst.lifecycle_state == "TERMINATED":
                            continue

                        _, _, nsg_ids, _ = get_instance_ips_and_nsgs(
                            session.compute_client,
                            session.virtual_network_client,
                            inst.compartment_id,
                            inst.id,
                        )

                        comp_name = compartment_names.get(inst.compartment_id, inst.compartment_id[:15] + "...")
                        if nsg_ids:
                            for nsg_id in nsg_ids:
                                rules_response = (
                                    session.virtual_network_client.list_network_security_group_security_rules(nsg_id)
                                )
                                if isinstance(rules_response, oci.response.Response):
                                    rules = rules_response.data
                                    print(
                                        f"   Instance: {inst.display_name} (Compartment: {comp_name}) "
                                        f"[NSG ID: {nsg_id[:25]}...]:"
                                    )
                                    for rule in rules:
                                        print(f"     * {format_security_rule(rule)}")
                                    print("   " + "-" * 80)
                        else:
                            print(
                                f"   Instance: {inst.display_name} (Compartment: {comp_name}) - "
                                f"(No Network Security Groups bound to this VNIC)"
                            )
                            print("   " + "-" * 80)
                    print("  " + "=" * 85)

            except Exception as e:
                logfire.error(f"Could not process account {account_name}: {e}")

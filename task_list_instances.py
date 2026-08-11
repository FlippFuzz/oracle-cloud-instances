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


def _protocol_and_ports(protocol: str, tcp_options, udp_options) -> tuple[str, str]:
    """Resolve a human-readable protocol name and port description for a security rule.

    Args:
        protocol: OCI protocol number string (e.g. "6", "17", "1", "58", "all").
        tcp_options: TCP options object from the rule, or None.
        udp_options: UDP options object from the rule, or None.

    Returns:
        A tuple of (protocol_name, port_description).
    """
    protocol_map = {
        "6": "TCP",
        "17": "UDP",
        "1": "ICMP",
        "58": "ICMPv6",
        "all": "All Protocols",
    }
    proto = protocol_map.get(protocol, f"Proto {protocol}")

    ports = "All Ports"
    if protocol == "6" and tcp_options:
        r = tcp_options.destination_port_range
        if r:
            ports = f"Port {r.min}" if r.min == r.max else f"Ports {r.min}-{r.max}"
    elif protocol == "17" and udp_options:
        r = udp_options.destination_port_range
        if r:
            ports = f"Port {r.min}" if r.min == r.max else f"Ports {r.min}-{r.max}"

    return proto, ports


def format_security_rule(rule) -> str:
    """Convert a native OCI NSG SecurityRule model into human-readable text.

    Args:
        rule: OCI NSG SecurityRule object.

    Returns:
        Human-readable representation of the security rule.
    """
    if rule.direction == "EGRESS":
        return f"Allow Outbound traffic to {rule.destination} [Protocol: {rule.protocol}]"

    proto, ports = _protocol_and_ports(rule.protocol, rule.tcp_options, rule.udp_options)
    desc = f" [{rule.description}]" if rule.description else ""
    return f"Allow {proto} from {rule.source} on {ports}{desc}"


def format_security_list_rule(rule, direction: str) -> str:
    """Convert an OCI Security List ingress/egress rule into human-readable text.

    Args:
        rule: OCI IngressSecurityRule or EgressSecurityRule object.
        direction: Either "INGRESS" or "EGRESS", since the OCI SDK returns these
            as two separate lists without a direction field on the rule itself.

    Returns:
        Human-readable representation of the security rule.
    """
    if direction == "EGRESS":
        return f"Allow Outbound traffic to {rule.destination} [Protocol: {rule.protocol}]"

    proto, ports = _protocol_and_ports(rule.protocol, rule.tcp_options, rule.udp_options)
    desc = f" [{rule.description}]" if rule.description else ""
    return f"Allow {proto} from {rule.source} on {ports}{desc}"


def get_instance_subnet_ids(compute_client, virtual_network_client, compartment_id: str, instance_id: str) -> list:
    """Retrieve the distinct subnet OCIDs backing an instance's VNIC attachments.

    Args:
        compute_client: OCI ComputeClient instance.
        virtual_network_client: OCI VirtualNetworkClient instance.
        compartment_id: OCID of the compartment.
        instance_id: OCID of the compute instance.

    Returns:
        A list of unique subnet OCIDs used by the instance's VNICs, in discovery order.
    """
    subnet_ids = []
    try:
        attachments_response = oci.pagination.list_call_get_all_results(
            compute_client.list_vnic_attachments,
            compartment_id=compartment_id,
            instance_id=instance_id,
        )
        if isinstance(attachments_response, oci.response.Response):
            for attachment in attachments_response.data:
                vnic_response = virtual_network_client.get_vnic(attachment.vnic_id)
                if isinstance(vnic_response, oci.response.Response) and vnic_response.data.subnet_id:
                    subnet_ids.append(vnic_response.data.subnet_id)
    except Exception as e:
        logfire.warning(f"Failed to resolve subnet(s) for instance {instance_id}: {e}")
    return list(dict.fromkeys(subnet_ids))


def get_security_lists_for_subnet(virtual_network_client, subnet_id: str) -> list:
    """Retrieve the Security List objects attached to a subnet.

    Args:
        virtual_network_client: OCI VirtualNetworkClient instance.
        subnet_id: OCID of the subnet.

    Returns:
        A list of OCI SecurityList objects attached to the subnet.
    """
    security_lists = []
    try:
        subnet_response = virtual_network_client.get_subnet(subnet_id)
        if isinstance(subnet_response, oci.response.Response):
            for sl_id in subnet_response.data.security_list_ids or []:
                sl_response = virtual_network_client.get_security_list(sl_id)
                if isinstance(sl_response, oci.response.Response):
                    security_lists.append(sl_response.data)
    except Exception as e:
        logfire.warning(f"Failed to resolve security lists for subnet {subnet_id}: {e}")
    return security_lists


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

                # Fetch and display the effective Security List rules for each subnet in use.
                # These apply in addition to (not instead of) any NSG rules shown above.
                if instances:
                    subnet_instance_names: dict[str, list[str]] = {}
                    for inst in instances:
                        if inst.lifecycle_state == "TERMINATED":
                            continue
                        for subnet_id in get_instance_subnet_ids(
                            session.compute_client, session.virtual_network_client, inst.compartment_id, inst.id
                        ):
                            subnet_instance_names.setdefault(subnet_id, []).append(inst.display_name)

                    if subnet_instance_names:
                        print("\n  Active Subnet Security List Rules (apply in addition to any NSG rules above):")
                        print("  " + "=" * 85)
                        for subnet_id, instance_names in subnet_instance_names.items():
                            subnet_response = session.virtual_network_client.get_subnet(subnet_id)
                            subnet_name = (
                                subnet_response.data.display_name
                                if isinstance(subnet_response, oci.response.Response)
                                else subnet_id
                            )

                            print(f"   Subnet: {subnet_name} (Instances: {', '.join(instance_names)})")

                            security_lists = get_security_lists_for_subnet(session.virtual_network_client, subnet_id)
                            if not security_lists:
                                print("     (No Security Lists found)")
                            for sl in security_lists:
                                print(f"     Security List: {sl.display_name}")
                                for rule in sl.ingress_security_rules:
                                    print(f"       * {format_security_list_rule(rule, 'INGRESS')}")
                                for rule in sl.egress_security_rules:
                                    print(f"       * {format_security_list_rule(rule, 'EGRESS')}")
                            print("   " + "-" * 80)
                        print("  " + "=" * 85)

            except Exception as e:
                logfire.error(f"Could not process account {account_name}: {e}")

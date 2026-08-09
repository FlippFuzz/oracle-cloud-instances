"""Script to tear down and delete all OCI resources associated with an account."""

import configparser
import os
import sys
import time

import logfire
import oci

from common import (
    OCI_CONFIG_FILE,
    AccountSession,
)


def get_vcn_defaults(virtual_network_client, compartment_id: str) -> set:
    """Collect IDs of default VCN resources that are automatically deleted with VCNs.

    Args:
        virtual_network_client: OCI VirtualNetworkClient instance.
        compartment_id: OCID of the compartment.

    Returns:
        A set of resource IDs for default VCN resources.
    """
    defaults = set()
    try:
        vcns = oci.pagination.list_call_get_all_results(
            virtual_network_client.list_vcns, compartment_id=compartment_id
        ).data
        for vcn in vcns:
            if vcn.default_security_list_id:
                defaults.add(vcn.default_security_list_id)
            if vcn.default_route_table_id:
                defaults.add(vcn.default_route_table_id)
            if vcn.default_dhcp_options_id:
                defaults.add(vcn.default_dhcp_options_id)
    except Exception as e:
        logfire.warning("Could not fetch default VCN resources", error=str(e))
    return defaults


def list_resources_for_account(session: AccountSession) -> dict:
    """Gather all target OCI resources in the compartment for deletion.

    Args:
        session: AccountSession instance containing OCI clients and context.

    Returns:
        A dictionary mapping resource categories to lists of resource objects.
    """
    c_id = session.compartment_id
    vn_client = session.virtual_network_client
    comp_client = session.compute_client

    with logfire.span("Scanning account resources", account=session.account_name, compartment_id=c_id):
        # Get default routing/security resources to exclude them from manual deletion
        default_resource_ids = get_vcn_defaults(vn_client, c_id)

        # 1. Compute Instances (exclude TERMINATED)
        instances = []
        try:
            raw_instances = oci.pagination.list_call_get_all_results(
                comp_client.list_instances, compartment_id=c_id
            ).data
            instances = [i for i in raw_instances if i.lifecycle_state != "TERMINATED"]
        except Exception as e:
            logfire.error("Error listing instances", error=str(e))

        # 2. VCNs
        vcns = []
        try:
            vcns = oci.pagination.list_call_get_all_results(vn_client.list_vcns, compartment_id=c_id).data
        except Exception as e:
            logfire.error("Error listing VCNs", error=str(e))

        # 3. Subnets
        subnets = []
        try:
            subnets = oci.pagination.list_call_get_all_results(vn_client.list_subnets, compartment_id=c_id).data
        except Exception as e:
            logfire.error("Error listing subnets", error=str(e))

        # 4. Network Security Groups
        nsgs = []
        try:
            nsgs = oci.pagination.list_call_get_all_results(
                vn_client.list_network_security_groups, compartment_id=c_id
            ).data
        except Exception as e:
            logfire.error("Error listing NSGs", error=str(e))

        # 5. Gateways (Internet, NAT, Service, LPGs)
        igws, nat_gws, sgws, lpgs = [], [], [], []
        try:
            igws = oci.pagination.list_call_get_all_results(vn_client.list_internet_gateways, compartment_id=c_id).data
        except Exception as e:
            logfire.error("Error listing Internet Gateways", error=str(e))

        try:
            nat_gws = oci.pagination.list_call_get_all_results(vn_client.list_nat_gateways, compartment_id=c_id).data
        except Exception as e:
            logfire.error("Error listing NAT Gateways", error=str(e))

        try:
            sgws = oci.pagination.list_call_get_all_results(vn_client.list_service_gateways, compartment_id=c_id).data
        except Exception as e:
            logfire.error("Error listing Service Gateways", error=str(e))

        try:
            lpgs = oci.pagination.list_call_get_all_results(
                vn_client.list_local_peering_gateways, compartment_id=c_id
            ).data
        except Exception as e:
            logfire.error("Error listing LPGs", error=str(e))

        # 6. Custom Security Lists (exclude defaults)
        security_lists = []
        try:
            raw_sls = oci.pagination.list_call_get_all_results(vn_client.list_security_lists, compartment_id=c_id).data
            security_lists = [s for s in raw_sls if s.id not in default_resource_ids]
        except Exception as e:
            logfire.error("Error listing Security Lists", error=str(e))

        # 7. Custom Route Tables (exclude defaults)
        route_tables = []
        try:
            raw_rts = oci.pagination.list_call_get_all_results(vn_client.list_route_tables, compartment_id=c_id).data
            route_tables = [r for r in raw_rts if r.id not in default_resource_ids]
        except Exception as e:
            logfire.error("Error listing Route Tables", error=str(e))

        # 8. Reserved IPs (Regional Scope)
        reserved_ips = []
        try:
            raw_ips = oci.pagination.list_call_get_all_results(
                vn_client.list_public_ips, scope="REGION", compartment_id=c_id
            ).data
            reserved_ips = [ip for ip in raw_ips if ip.lifetime == "RESERVED"]
        except Exception as e:
            logfire.error("Error listing public IPs", error=str(e))

    return {
        "instances": instances,
        "vcns": vcns,
        "subnets": subnets,
        "nsgs": nsgs,
        "igws": igws,
        "nat_gws": nat_gws,
        "sgws": sgws,
        "lpgs": lpgs,
        "security_lists": security_lists,
        "route_tables": route_tables,
        "reserved_ips": reserved_ips,
    }


def retry_resource_deletion(
    delete_fn, resource_id: str, resource_name: str, max_retries: int = 6, delay: int = 10
) -> bool:
    """Safely retry resource deletions to account for asynchronous API releases.

    Args:
        delete_fn: Callable function to delete the resource.
        resource_id: OCID of the resource to delete.
        resource_name: Human-readable name of the resource type.
        max_retries: Maximum number of deletion attempts.
        delay: Delay in seconds between retry attempts.

    Returns:
        True if deletion succeeded or resource was not found, False if all retries failed.
    """
    with logfire.span("Deleting OCI resource", resource_name=resource_name, resource_id=resource_id):
        for attempt in range(1, max_retries + 1):
            try:
                delete_fn(resource_id)
                logfire.info(f"Successfully deleted {resource_name}: {resource_id}")
                return True
            except oci.exceptions.ServiceError as e:
                if e.status == 404:
                    logfire.info(f"{resource_name} not found or already deleted: {resource_id}")
                    return True
                if attempt == max_retries:
                    logfire.error(
                        f"Failed to delete {resource_name} {resource_id} after {max_retries} attempts: {e.message}"
                    )
                    return False
                logfire.warning(
                    f"[Attempt {attempt}/{max_retries}] Waiting {delay}s to retry {resource_name}",
                    error_message=e.message,
                )
                time.sleep(delay)
        return False


def execute_deletion_for_account(session: AccountSession, resources: dict):
    """Delete resources in the strict required dependency order.

    Args:
        session: AccountSession instance containing OCI clients and context.
        resources: Dictionary mapping resource categories to lists of resources.
    """
    c_id = session.compartment_id
    vn_client = session.virtual_network_client
    comp_client = session.compute_client
    identity_client = session.identity_client

    with logfire.span(
        "Executing account deletion teardown",
        account=session.account_name,
        compartment_id=c_id,
    ):
        # 1. Terminate Instances
        if resources["instances"]:
            with logfire.span("Terminating compute instances"):
                for inst in resources["instances"]:
                    try:
                        comp_client.terminate_instance(inst.id, preserve_boot_volume=False)
                        logfire.info(f"Issued termination request for instance: {inst.display_name} ({inst.id})")
                    except Exception as e:
                        logfire.error(f"Error terminating instance {inst.id}: {e}")

                logfire.info("Waiting for all instances to be fully TERMINATED...")
                while True:
                    active_instances = []
                    try:
                        raw_instances = oci.pagination.list_call_get_all_results(
                            comp_client.list_instances, compartment_id=c_id
                        ).data
                        active_instances = [i for i in raw_instances if i.lifecycle_state != "TERMINATED"]
                    except Exception as e:
                        logfire.error(f"Error checking instance states: {e}")

                    if not active_instances:
                        logfire.info("All compute instances have been terminated and released.")
                        break

                    logfire.info(f"Waiting on {len(active_instances)} instance(s) to finish terminating...")
                    time.sleep(10)

        # 2. Clear route rules in all route tables (Default & Custom) to break gateway dependencies
        try:
            all_route_tables = oci.pagination.list_call_get_all_results(
                vn_client.list_route_tables, compartment_id=c_id
            ).data
            if all_route_tables:
                with logfire.span("Clearing route tables to release gateway references"):
                    for rt in all_route_tables:
                        try:
                            vn_client.update_route_table(
                                rt.id,
                                oci.core.models.UpdateRouteTableDetails(route_rules=[]),
                            )
                            logfire.info(f"Cleared rules for route table: {rt.display_name} ({rt.id})")
                        except Exception as e:
                            logfire.error(f"Could not clear route table {rt.id}: {e}")
        except Exception as e:
            logfire.warning(f"Failed to list route tables to clear rules: {e}")

        # 3. Local Peering Gateways (LPGs)
        if resources["lpgs"]:
            with logfire.span("Deleting LPGs"):
                for lpg in resources["lpgs"]:
                    retry_resource_deletion(
                        vn_client.delete_local_peering_gateway,
                        lpg.id,
                        "Local Peering Gateway",
                    )

        # 4. NAT Gateways
        if resources["nat_gws"]:
            with logfire.span("Deleting NAT Gateways"):
                for nat in resources["nat_gws"]:
                    retry_resource_deletion(vn_client.delete_nat_gateway, nat.id, "NAT Gateway")

        # 5. Service Gateways
        if resources["sgws"]:
            with logfire.span("Deleting Service Gateways"):
                for sgw in resources["sgws"]:
                    retry_resource_deletion(vn_client.delete_service_gateway, sgw.id, "Service Gateway")

        # 6. Internet Gateways
        if resources["igws"]:
            with logfire.span("Deleting Internet Gateways"):
                for igw in resources["igws"]:
                    retry_resource_deletion(vn_client.delete_internet_gateway, igw.id, "Internet Gateway")

        # 7. Network Security Groups
        if resources["nsgs"]:
            with logfire.span("Deleting Network Security Groups"):
                for nsg in resources["nsgs"]:
                    retry_resource_deletion(
                        vn_client.delete_network_security_group,
                        nsg.id,
                        "Network Security Group",
                    )

        # 8. Custom Security Lists
        if resources["security_lists"]:
            with logfire.span("Deleting Custom Security Lists"):
                for sl in resources["security_lists"]:
                    retry_resource_deletion(vn_client.delete_security_list, sl.id, "Security List")

        # 9. Custom Route Tables
        if resources["route_tables"]:
            with logfire.span("Deleting Custom Route Tables"):
                for rt in resources["route_tables"]:
                    retry_resource_deletion(vn_client.delete_route_table, rt.id, "Route Table")

        # 10. Subnets
        if resources["subnets"]:
            with logfire.span("Deleting Subnets"):
                for subnet in resources["subnets"]:
                    retry_resource_deletion(
                        vn_client.delete_subnet,
                        subnet.id,
                        "Subnet",
                        max_retries=10,
                        delay=15,
                    )

        # 11. VCNs
        if resources["vcns"]:
            with logfire.span("Deleting VCNs"):
                for vcn in resources["vcns"]:
                    retry_resource_deletion(vn_client.delete_vcn, vcn.id, "VCN", max_retries=10, delay=15)

        # 12. Reserved IPs
        if resources["reserved_ips"]:
            with logfire.span("Deleting Reserved IPs"):
                for ip in resources["reserved_ips"]:
                    retry_resource_deletion(
                        vn_client.delete_public_ip,
                        ip.id,
                        f"Reserved IP ({ip.ip_address})",
                    )

        # 13. Compartment Deletion
        if not c_id.startswith("ocid1.tenancy."):
            with logfire.span("Deleting Compartment", compartment_id=c_id):
                try:
                    identity_client.delete_compartment(c_id)
                    logfire.info(f"Issued deletion command for compartment {c_id}.")
                except Exception as e:
                    logfire.warning(f"Compartment deletion could not complete: {e}")
        else:
            logfire.info("Compartment targeted is the tenancy root and cannot be deleted.")


def main():
    """Run interactive OCI account teardown and deletion process."""
    # Parse OCI config to dynamically query configured profile names
    profiles = []
    if os.path.exists(OCI_CONFIG_FILE):
        try:
            parser = configparser.ConfigParser()
            parser.read(OCI_CONFIG_FILE)
            profiles = parser.sections()
        except Exception as e:
            logfire.warning(f"Could not parse {OCI_CONFIG_FILE}: {e}")

    print("\n" + "=" * 80)
    print("               OCI RESOURCE TEARDOWN TOOL")
    print("=" * 80)
    if profiles:
        print("Available accounts (profiles) found in OCI config:")
        for idx, p in enumerate(profiles, 1):
            print(f"  [{idx}] {p}")

        choice = input("\nSelect an account by number, or type profile name manually: ").strip()
        if choice.isdigit():
            val = int(choice)
            if 1 <= val <= len(profiles):
                account_name = profiles[val - 1]
            else:
                print("Invalid selection. Exiting.")
                sys.exit(1)
        else:
            account_name = choice
    else:
        account_name = input("Enter OCI profile/account name: ").strip()

    if not account_name:
        print("No account name provided. Exiting.")
        sys.exit(1)

    sessions: dict[str, AccountSession] = {}
    staged_resources: dict[str, dict] = {}
    has_resources_to_delete = False

    with logfire.span("Scanning account for resources to tear down", account=account_name):
        try:
            session = AccountSession.from_account(account_name, OCI_CONFIG_FILE)
            sessions[account_name] = session

            resources = list_resources_for_account(session)
            staged_resources[account_name] = resources

            # Evaluate if any active resources exist
            for key, val in resources.items():
                if val:
                    has_resources_to_delete = True
        except Exception as e:
            logfire.error(f"Could not connect or process account {account_name}", error=str(e))
            sys.exit(1)

    if not has_resources_to_delete:
        logfire.info(f"Compartment in {account_name} is completely clean. No resources found to delete.")
        sys.exit(0)

    # Display Confirmation Report on standard stdout for user interaction
    print("\n" + "=" * 80)
    print("               OCI RESOURCE TEARDOWN AND MIGRATION REPORT")
    print("=" * 80)
    for name, resources in staged_resources.items():
        print(f"\nAccount: {name}")
        print("-" * 50)

        inst_names = [f"{i.display_name} ({i.id[:20]}...)" for i in resources["instances"]]
        print(f"  Compute Instances ({len(inst_names)}): {', '.join(inst_names) if inst_names else 'None'}")

        nsg_names = [f"{n.display_name} ({n.id[:20]}...)" for n in resources["nsgs"]]
        print(f"  Network Security Groups ({len(nsg_names)}): {', '.join(nsg_names) if nsg_names else 'None'}")

        sl_names = [f"{s.display_name} ({s.id[:20]}...)" for s in resources["security_lists"]]
        print(f"  Custom Security Lists ({len(sl_names)}): {', '.join(sl_names) if sl_names else 'None'}")

        rt_names = [f"{r.display_name} ({r.id[:20]}...)" for r in resources["route_tables"]]
        print(f"  Custom Route Tables ({len(rt_names)}): {', '.join(rt_names) if rt_names else 'None'}")

        sub_names = [f"{s.display_name} ({s.id[:20]}...)" for s in resources["subnets"]]
        print(f"  Subnets ({len(sub_names)}): {', '.join(sub_names) if sub_names else 'None'}")

        igw_names = [f"{g.display_name} ({g.id[:20]}...)" for g in resources["igws"]]
        print(f"  Internet Gateways ({len(igw_names)}): {', '.join(igw_names) if igw_names else 'None'}")

        nat_names = [f"{g.display_name} ({g.id[:20]}...)" for g in resources["nat_gws"]]
        print(f"  NAT Gateways ({len(nat_names)}): {', '.join(nat_names) if nat_names else 'None'}")

        sgw_names = [f"{g.display_name} ({g.id[:20]}...)" for g in resources["sgws"]]
        print(f"  Service Gateways ({len(sgw_names)}): {', '.join(sgw_names) if sgw_names else 'None'}")

        lpg_names = [f"{g.display_name} ({g.id[:20]}...)" for g in resources["lpgs"]]
        print(f"  Local Peering Gateways ({len(lpg_names)}): {', '.join(lpg_names) if lpg_names else 'None'}")

        vcn_names = [f"{v.display_name} ({v.id[:20]}...)" for v in resources["vcns"]]
        print(f"  VCNs ({len(vcn_names)}): {', '.join(vcn_names) if vcn_names else 'None'}")

        ip_names = [f"{ip.ip_address} ({ip.id[:20]}...)" for ip in resources["reserved_ips"]]
        print(f"  Reserved IPs ({len(ip_names)}): {', '.join(ip_names) if ip_names else 'None'}")

    print("\n" + "=" * 80)
    print("WARNING: This script will permanently delete all resources listed above.")
    print("This action is irreversible. Boot volumes associated with instances will be deleted.")
    print("=" * 80)

    confirmation = input("\nAre you sure you want to delete all listed OCI resources? (type 'yes' to confirm): ")
    if confirmation.strip().lower() != "yes":
        logfire.info("Deletion canceled by user.")
        sys.exit(0)

    # Proceed with clean deletion for the specified account
    for name, resources in staged_resources.items():
        session = sessions[name]
        execute_deletion_for_account(session, resources)

    logfire.info("Resource cleanup processes completed successfully.")


if __name__ == "__main__":
    logfire.configure(send_to_logfire="if-token-present", scrubbing=False)
    main()

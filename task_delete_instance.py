"""Script to interactively select and terminate an OCI compute instance and clean up associated resources."""

import configparser
import os
import sys
import time
from typing import Optional

import logfire
import oci

from common import (
    OCI_CONFIG_FILE,
    AccountSession,
    log_detailed_service_error,
)


def select_account() -> str:
    """Prompt the user to select an OCI account/profile from OCI_CONFIG_FILE.

    Returns:
        The selected account/profile name.
    """
    profiles = []
    if os.path.exists(OCI_CONFIG_FILE):
        try:
            parser = configparser.ConfigParser()
            parser.read(OCI_CONFIG_FILE)
            profiles = parser.sections()
        except Exception as e:
            logfire.warning(f"Could not parse {OCI_CONFIG_FILE}: {e}")

    print("\n" + "=" * 80)
    print("               OCI INSTANCE TERMINATION TOOL")
    print("=" * 80)
    if profiles:
        print("Available accounts (profiles) found in OCI config:")
        for idx, p in enumerate(profiles, 1):
            print(f"  [{idx}] {p}")

        choice = input("\nSelect an account by number, or type profile name manually: ").strip()
        if choice.isdigit():
            val = int(choice)
            if 1 <= val <= len(profiles):
                return profiles[val - 1]
            print("Invalid selection. Exiting.")
            sys.exit(1)
        return choice

    account_name = input("Enter OCI profile/account name: ").strip()
    if not account_name:
        print("No account name provided. Exiting.")
        sys.exit(1)
    return account_name


def get_active_compartment_ids(session: AccountSession) -> dict[str, str]:
    """Retrieve the tenancy root plus all active sub-compartment IDs, mapped to display names.

    Args:
        session: AccountSession instance containing OCI clients and context.

    Returns:
        A dict mapping compartment OCID to a human-readable compartment name.
    """
    compartment_names = {session.compartment_id: "Root Tenancy"}
    try:
        compartments_response = oci.pagination.list_call_get_all_results(
            session.identity_client.list_compartments,
            session.compartment_id,
            compartment_id_in_subtree=True,
        )
        if isinstance(compartments_response, oci.response.Response):
            for comp in compartments_response.data:
                if comp.lifecycle_state == "ACTIVE":
                    compartment_names[comp.id] = comp.name
    except Exception as e:
        logfire.warning(f"Could not list sub-compartments for {session.account_name}: {e}")
    return compartment_names


def list_active_instances(
    session: AccountSession,
    compartment_names: dict[str, str],
) -> list[tuple[oci.core.models.Instance, str]]:
    """Retrieve all non-terminated compute instances across active compartments.

    Args:
        session: AccountSession instance containing OCI clients and context.
        compartment_names: Mapping of compartment OCID to display name to search across.

    Returns:
        A list of (instance, compartment_name) tuples found in the account.
    """
    instances = []
    for comp_id, comp_name in compartment_names.items():
        try:
            list_response = oci.pagination.list_call_get_all_results(
                session.compute_client.list_instances,
                compartment_id=comp_id,
            )
            if not isinstance(list_response, oci.response.Response) or not list_response.data:
                continue
            for inst in list_response.data:
                if inst.lifecycle_state not in ["TERMINATED", "TERMINATING"]:
                    instances.append((inst, comp_name))
        except Exception as e:
            logfire.warning(f"Could not list instances in compartment {comp_id}: {e}")
    return instances


def confirm(prompt: str, default: bool = False) -> bool:
    """Prompt the user for a yes/no confirmation.

    Args:
        prompt: The question to ask the user.
        default: Default value if user presses Enter without typing.

    Returns:
        True if the user confirmed, False otherwise.
    """
    suffix = " [Y/n]: " if default else " [y/N]: "
    while True:
        try:
            response = input(f"{prompt}{suffix}").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            return False
        if not response:
            return default
        if response in ("y", "yes"):
            return True
        if response in ("n", "no"):
            return False
        print("Please answer 'yes' (y) or 'no' (n).")


def get_instance_boot_volumes(
    compute_client: oci.core.ComputeClient,
    block_storage_client: oci.core.BlockstorageClient,
    compartment_id: str,
    instance_id: str,
    availability_domain: str,
) -> list[oci.core.models.BootVolume]:
    """Retrieve the boot volume objects attached to an instance.

    Args:
        compute_client: OCI ComputeClient instance.
        block_storage_client: OCI BlockstorageClient instance.
        compartment_id: OCID of the compartment.
        instance_id: OCID of the compute instance.
        availability_domain: Name of the availability domain.

    Returns:
        A list of OCI BootVolume objects attached to the instance.
    """
    boot_volumes = []
    try:
        attachments_response = compute_client.list_boot_volume_attachments(
            availability_domain=availability_domain,
            compartment_id=compartment_id,
            instance_id=instance_id,
        )
        if isinstance(attachments_response, oci.response.Response) and attachments_response.data:
            for attachment in attachments_response.data:
                if attachment.lifecycle_state not in ["TERMINATED", "TERMINATING"] and attachment.boot_volume_id:
                    bv_response = block_storage_client.get_boot_volume(attachment.boot_volume_id)
                    if isinstance(bv_response, oci.response.Response) and bv_response.data:
                        boot_volumes.append(bv_response.data)
    except Exception as e:
        logfire.warning(f"Could not retrieve boot volumes for instance {instance_id}: {e}")
    return boot_volumes


def find_dedicated_nsg(
    virtual_network_client: oci.core.VirtualNetworkClient,
    compartment_id: str,
    server_name: str,
) -> Optional[oci.core.models.NetworkSecurityGroup]:
    """Find a dedicated Network Security Group created for a specific server name.

    Args:
        virtual_network_client: OCI VirtualNetworkClient instance.
        compartment_id: OCID of the compartment.
        server_name: Name of the server.

    Returns:
        The NetworkSecurityGroup object if found, or None.
    """
    nsg_name = f"{server_name}-nsg"
    try:
        nsgs_response = oci.pagination.list_call_get_all_results(
            virtual_network_client.list_network_security_groups,
            compartment_id=compartment_id,
        )
        if isinstance(nsgs_response, oci.response.Response) and nsgs_response.data:
            for nsg in nsgs_response.data:
                if nsg.display_name == nsg_name and nsg.lifecycle_state != "TERMINATED":
                    return nsg
    except Exception as e:
        logfire.warning(f"Could not search for NSG '{nsg_name}': {e}")
    return None


def get_reserved_public_ip_for_vnic(
    virtual_network_client: oci.core.VirtualNetworkClient,
    vnic_id: str,
) -> Optional[oci.core.models.PublicIp]:
    """Check if the VNIC is associated with a reserved public IP.

    Args:
        virtual_network_client: OCI VirtualNetworkClient instance.
        vnic_id: OCID of the VNIC.

    Returns:
        The PublicIp object if a reserved public IP is attached, or None.
    """
    try:
        private_ips_response = virtual_network_client.list_private_ips(vnic_id=vnic_id)
        if isinstance(private_ips_response, oci.response.Response) and private_ips_response.data:
            primary_private_ip = private_ips_response.data[0]
            if primary_private_ip.id:
                details = oci.core.models.GetPublicIpByPrivateIpIdDetails(private_ip_id=primary_private_ip.id)
                public_ip_response = virtual_network_client.get_public_ip_by_private_ip_id(details)
                if (
                    isinstance(public_ip_response, oci.response.Response)
                    and public_ip_response.data.lifetime == "RESERVED"
                ):
                    return public_ip_response.data
    except oci.exceptions.ServiceError as e:
        if e.status != 404:
            logfire.warning(f"Error checking reserved public IP on VNIC {vnic_id}: {e}")
    except Exception as e:
        logfire.warning(f"Error checking reserved public IP on VNIC {vnic_id}: {e}")
    return None


def delete_nsg_with_retry(
    virtual_network_client: oci.core.VirtualNetworkClient,
    nsg_id: str,
    max_retries: int = 6,
    delay_seconds: int = 5,
):
    """Delete a Network Security Group with retry logic while VNIC disassociations propagate.

    Args:
        virtual_network_client: OCI VirtualNetworkClient instance.
        nsg_id: OCID of the NSG to delete.
        max_retries: Maximum number of retry attempts.
        delay_seconds: Seconds to wait between attempts.
    """
    for attempt in range(1, max_retries + 1):
        try:
            virtual_network_client.delete_network_security_group(nsg_id)
            logfire.info(f"Successfully deleted Network Security Group ({nsg_id}).")
            return
        except oci.exceptions.ServiceError as e:
            if attempt < max_retries:
                logfire.info(
                    f"Waiting for VNIC references to clear from NSG (attempt {attempt}/{max_retries}): {e.message}"
                )
                time.sleep(delay_seconds)
            else:
                log_detailed_service_error(e, nsg_id, "delete_network_security_group")


def main():
    """Run the interactive instance selection and deletion workflow."""
    account_name = select_account()

    with logfire.span(f"Connecting to account {account_name}"):
        try:
            session = AccountSession.from_account(account_name, OCI_CONFIG_FILE)
        except Exception as e:
            logfire.error(f"Could not connect to account {account_name}: {e}")
            sys.exit(1)

    with logfire.span(f"Scanning instances for {account_name}"):
        compartment_names = get_active_compartment_ids(session)
        instances_with_comps = list_active_instances(session, compartment_names)

    if not instances_with_comps:
        print(f"\nNo active instances found in account '{account_name}'. Nothing to do.")
        sys.exit(0)

    print("\n" + "=" * 80)
    print(f"  Active instances in account '{account_name}'")
    print("=" * 80)
    for idx, (inst, comp_name) in enumerate(instances_with_comps, 1):
        print(f"  [{idx}] {inst.display_name:<20} [{inst.lifecycle_state:<8}] ({inst.shape})")
        print(f"      Compartment: {comp_name} | AD: {inst.availability_domain}")
        print(f"      OCID: {inst.id}")
    print("=" * 80)

    selection = input(f"\nSelect an instance to delete [1-{len(instances_with_comps)}], or 'q' to quit: ").strip()
    if selection.lower() in ("q", "quit", "exit", ""):
        print("Aborted. No changes made.")
        sys.exit(0)

    if not selection.isdigit() or not (1 <= int(selection) <= len(instances_with_comps)):
        print("Invalid selection. Exiting.")
        sys.exit(1)

    target_instance, target_comp_name = instances_with_comps[int(selection) - 1]

    instance_id = target_instance.id
    instance_name = target_instance.display_name or "Unknown"
    availability_domain = target_instance.availability_domain
    compartment_id = target_instance.compartment_id or session.compartment_id

    if not instance_id or not availability_domain:
        print("Instance is missing critical OCID or Availability Domain attributes. Exiting.")
        sys.exit(1)

    print("\n" + "=" * 80)
    print(f" Selected Instance: {instance_name}")
    print("=" * 80)
    print(f" - OCID:                {instance_id}")
    print(f" - State:               {target_instance.lifecycle_state}")
    print(f" - Shape:               {target_instance.shape}")
    print(f" - Availability Domain: {availability_domain}")
    print(f" - Compartment:         {target_comp_name} ({compartment_id})")

    # 1. Inspect Boot Volumes
    boot_volumes = get_instance_boot_volumes(
        session.compute_client,
        session.block_storage_client,
        compartment_id,
        instance_id,
        availability_domain,
    )

    # 2. Inspect Attached VNICs and Reserved IPs
    vnic_ids: list[str] = []
    reserved_ips: list[oci.core.models.PublicIp] = []
    try:
        attachments_res = session.compute_client.list_vnic_attachments(
            compartment_id=compartment_id,
            instance_id=instance_id,
        )
        if isinstance(attachments_res, oci.response.Response) and attachments_res.data:
            for att in attachments_res.data:
                if att.lifecycle_state not in ["TERMINATED", "TERMINATING"] and att.vnic_id:
                    vnic_ids.append(att.vnic_id)
                    res_ip = get_reserved_public_ip_for_vnic(session.virtual_network_client, att.vnic_id)
                    if res_ip:
                        reserved_ips.append(res_ip)
    except Exception as e:
        logfire.warning(f"Could not audit VNICs: {e}")

    # 3. Inspect Dedicated NSG
    dedicated_nsg = find_dedicated_nsg(
        session.virtual_network_client,
        compartment_id,
        instance_name,
    )

    print("\n Associated Resources:")
    if boot_volumes:
        for bv in boot_volumes:
            print(f" - Boot Volume:         {bv.display_name} ({bv.size_in_gbs} GB) [ID: {bv.id}]")
    else:
        print(" - Boot Volume:         (None found attached)")

    if vnic_ids:
        print(
            f" - VNICs ({len(vnic_ids)}):           "
            "Will be terminated automatically by OCI along with ephemeral IPv4/IPv6 blocks."
        )

    if reserved_ips:
        for rip in reserved_ips:
            print(f" - Reserved Public IP:  {rip.ip_address} [ID: {rip.id}]")

    if dedicated_nsg:
        print(f" - Dedicated NSG:       {dedicated_nsg.display_name} [ID: {dedicated_nsg.id}]")
    else:
        print(" - Dedicated NSG:       (None found)")
    print("=" * 80)

    # Confirmations
    print("\nPlease confirm the deletion of each resource:\n")

    delete_instance = confirm(
        f"[1] Terminate compute instance '{instance_name}' ({instance_id})?",
        default=False,
    )

    if not delete_instance:
        print("\nAborted. No resources were modified.")
        sys.exit(0)

    delete_boot_volume = False
    if boot_volumes:
        bv_summary = ", ".join(f"{bv.display_name or 'Boot Volume'} ({bv.size_in_gbs} GB)" for bv in boot_volumes)
        delete_boot_volume = confirm(
            f"[2] Permanently delete attached boot volume(s): {bv_summary}?",
            default=False,
        )

    delete_nsg = False
    if dedicated_nsg:
        delete_nsg = confirm(
            f"[3] Delete dedicated Network Security Group '{dedicated_nsg.display_name}' ({dedicated_nsg.id})?",
            default=False,
        )

    delete_res_ips = False
    if reserved_ips:
        ip_summary = ", ".join(rip.ip_address for rip in reserved_ips if rip.ip_address)
        delete_res_ips = confirm(
            f"[4] Delete associated Reserved Public IP(s) ({ip_summary})?",
            default=False,
        )

    print("\n--- Executing Requested Actions ---")

    # Step A: Terminate Instance (with boot volume flag)
    logfire.info(f"Terminating instance '{instance_name}' (preserve_boot_volume={not delete_boot_volume})...")
    try:
        session.compute_client.terminate_instance(
            instance_id,
            preserve_boot_volume=not delete_boot_volume,
        )
        print(f"[*] Terminate request sent for instance '{instance_name}'. Waiting for completion...")

        oci.wait_until(
            session.compute_client,
            session.compute_client.get_instance(instance_id),
            "lifecycle_state",
            "TERMINATED",
            max_wait_seconds=600,
        )
        print(f"[✓] Instance '{instance_name}' is now TERMINATED.")
    except Exception as e:
        logfire.error(f"Failed during instance termination: {e}")
        sys.exit(1)

    # Step B: Double-check boot volume status if requested
    if delete_boot_volume and boot_volumes:
        for bv in boot_volumes:
            if not bv.id:
                continue
            try:
                bv_res = session.block_storage_client.get_boot_volume(bv.id)
                if isinstance(bv_res, oci.response.Response) and bv_res.data.lifecycle_state != "TERMINATED":
                    if bv_res.data.lifecycle_state != "TERMINATING":
                        logfire.info(f"Explicitly deleting boot volume {bv.id}...")
                        session.block_storage_client.delete_boot_volume(bv.id)
                    oci.wait_until(
                        session.block_storage_client,
                        session.block_storage_client.get_boot_volume(bv.id),
                        "lifecycle_state",
                        "TERMINATED",
                        max_wait_seconds=300,
                    )
                print(f"[✓] Boot Volume '{bv.display_name}' ({bv.size_in_gbs} GB) permanently deleted.")
            except oci.exceptions.ServiceError as se:
                if se.status == 404:
                    print(f"[✓] Boot Volume '{bv.display_name}' permanently deleted.")
                else:
                    logfire.warning(f"Could not verify deletion of boot volume {bv.id}: {se}")
            except Exception as e:
                logfire.warning(f"Error checking boot volume deletion {bv.id}: {e}")

    # Step C: Delete Dedicated NSG if requested
    if delete_nsg and dedicated_nsg and dedicated_nsg.id:
        print(f"[*] Deleting Network Security Group '{dedicated_nsg.display_name}'...")
        delete_nsg_with_retry(session.virtual_network_client, dedicated_nsg.id)
        print(f"[✓] Network Security Group '{dedicated_nsg.display_name}' deleted.")

    # Step D: Delete Reserved Public IPs if requested
    if delete_res_ips and reserved_ips:
        for rip in reserved_ips:
            if rip.id and rip.ip_address:
                try:
                    print(f"[*] Deleting Reserved Public IP {rip.ip_address}...")
                    session.virtual_network_client.delete_public_ip(rip.id)
                    print(f"[✓] Reserved Public IP {rip.ip_address} deleted.")
                except Exception as e:
                    logfire.warning(f"Failed to delete reserved public IP {rip.ip_address}: {e}")

    print("\n[✓] Cleanup complete! You can now run `python task_update_instances.py` to provision a fresh instance.")


if __name__ == "__main__":
    logfire.configure(send_to_logfire="if-token-present", scrubbing=False)
    main()

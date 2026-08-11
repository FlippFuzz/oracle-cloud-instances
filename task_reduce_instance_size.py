"""Script to reduce oversized VM.Standard.A1.Flex compute instances to fit reduced Always Free limits."""

import configparser
import os
import sys

import logfire
import oci

from common import (
    OCI_CONFIG_FILE,
    AccountSession,
    log_detailed_service_error,
)

TARGET_SHAPE = "VM.Standard.A1.Flex"
CURRENT_OCPUS = 4
CURRENT_MEMORY_IN_GBS = 24
NEW_OCPUS = 2
NEW_MEMORY_IN_GBS = 12


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
    print("               OCI INSTANCE DOWNSIZE TOOL")
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


def get_active_compartment_ids(session: AccountSession) -> dict:
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


def find_oversized_instances(session: AccountSession, compartment_names: dict) -> list:
    """Find A1.Flex instances still allocated at the old 4 OCPU / 24GB Always Free size.

    Args:
        session: AccountSession instance containing OCI clients and context.
        compartment_names: Mapping of compartment OCID to display name to search across.

    Returns:
        A list of (instance, compartment_name) tuples matching the target shape/size.
    """
    matches = []
    for comp_id, comp_name in compartment_names.items():
        try:
            list_response = oci.pagination.list_call_get_all_results(session.compute_client.list_instances, comp_id)
            if not isinstance(list_response, oci.response.Response):
                continue
        except Exception as e:
            logfire.warning(f"Could not list instances in compartment {comp_id}: {e}")
            continue

        for inst in list_response.data:
            if inst.lifecycle_state in ["TERMINATED", "TERMINATING"]:
                continue
            if inst.shape != TARGET_SHAPE:
                continue

            shape_config = inst.shape_config
            if not shape_config:
                continue

            ocpus = int(shape_config.ocpus) if shape_config.ocpus else None
            memory_in_gbs = int(shape_config.memory_in_gbs) if shape_config.memory_in_gbs else None
            if ocpus == CURRENT_OCPUS and memory_in_gbs == CURRENT_MEMORY_IN_GBS:
                matches.append((inst, comp_name))
    return matches


def resize_instance(session: AccountSession, instance) -> bool:
    """Reduce an instance's OCPU/memory allocation in place, without stopping it.

    Args:
        session: AccountSession instance containing OCI clients and context.
        instance: OCI Instance object to resize.

    Returns:
        True if the resize request was accepted by OCI, False otherwise.
    """
    update_details = oci.core.models.UpdateInstanceDetails(
        shape_config=oci.core.models.UpdateInstanceShapeConfigDetails(
            ocpus=NEW_OCPUS,
            memory_in_gbs=NEW_MEMORY_IN_GBS,
        ),
        # Default is UPDATE_OPERATION_CONSTRAINT_ALLOW_DOWNTIME
        # You get InvalidParameter if UPDATE_OPERATION_CONSTRAINT_AVOID_DOWNTIME is chosen
        update_operation_constraint=oci.core.models.UpdateInstanceDetails.UPDATE_OPERATION_CONSTRAINT_ALLOW_DOWNTIME,
    )
    try:
        response = session.compute_client.update_instance(instance.id, update_details)
        if not isinstance(response, oci.response.Response):
            logfire.error(f"Unexpected response type when resizing instance '{instance.display_name}'.")
            return False
        logfire.info(
            f"Resize request accepted for '{instance.display_name}'. "
            f"Current lifecycle state: {response.data.lifecycle_state}."
        )
        return True
    except oci.exceptions.ServiceError as e:
        log_detailed_service_error(e, instance.display_name, "update_instance")
        return False


def main():
    """Run the interactive instance downsizing workflow for a single OCI account."""
    account_name = select_account()

    with logfire.span(f"Connecting to account {account_name}"):
        try:
            session = AccountSession.from_account(account_name, OCI_CONFIG_FILE)
        except Exception as e:
            logfire.error(f"Could not connect to account {account_name}: {e}")
            sys.exit(1)

    with logfire.span(f"Scanning instances for {account_name}"):
        compartment_names = get_active_compartment_ids(session)
        matches = find_oversized_instances(session, compartment_names)

    if not matches:
        print(
            f"\nNo '{TARGET_SHAPE}' instances at {CURRENT_OCPUS} OCPU / {CURRENT_MEMORY_IN_GBS}GB RAM were found "
            f"in account '{account_name}'. Nothing to do."
        )
        sys.exit(0)

    print("\n" + "=" * 80)
    print(f"  Instances eligible for downsize in account '{account_name}'")
    print("=" * 80)
    for inst, comp_name in matches:
        print(f"  * {inst.display_name}  [{inst.lifecycle_state}]  (Compartment: {comp_name})")
        print(f"      {inst.id}")
    print("=" * 80)
    print(
        f"\nEach instance below can be reduced from {CURRENT_OCPUS} OCPU / {CURRENT_MEMORY_IN_GBS}GB RAM to "
        f"{NEW_OCPUS} OCPU / {NEW_MEMORY_IN_GBS}GB RAM."
    )
    print("This script will NOT stop or reboot the instance.")
    print("You must manually reboot it afterwards for the OS to recognize the new allocation.\n")

    resized = 0
    skipped = 0
    failed = 0

    for inst, comp_name in matches:
        confirmation = input(
            f"Resize '{inst.display_name}' (Compartment: {comp_name}) to {NEW_OCPUS} OCPU / "
            f"{NEW_MEMORY_IN_GBS}GB RAM? (type 'yes' to confirm, anything else to skip): "
        )
        if confirmation.strip().lower() != "yes":
            logfire.info(f"Skipped resize for '{inst.display_name}' at user request.")
            skipped += 1
            continue

        with logfire.span(f"Resizing instance {inst.display_name}"):
            if resize_instance(session, inst):
                resized += 1
            else:
                failed += 1

    print("\n" + "=" * 80)
    print(f"Done. Resized: {resized}  Skipped: {skipped}  Failed: {failed}")
    if resized:
        print("Remember to manually reboot the resized instance(s) to apply the new CPU/RAM allocation.")
    print("=" * 80)


if __name__ == "__main__":
    logfire.configure(send_to_logfire="if-token-present", scrubbing=False)
    main()

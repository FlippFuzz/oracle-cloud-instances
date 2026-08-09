"""Common helper utilities, data models, and OCI client wrappers."""

import inspect
import time
from typing import Dict, List, Optional

import logfire
import oci
from oci.core import (
    BlockstorageClient,
    ComputeClient,
    ComputeClientCompositeOperations,
    VirtualNetworkClient,
    VirtualNetworkClientCompositeOperations,
)
from oci.identity import IdentityClient
from oci.work_requests import WorkRequestClient
from pydantic import BaseModel, ConfigDict, model_validator
from pyrate_limiter import Duration, limiter_factory
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential
from yaml import safe_load

CONFIG_FILE = "config.yaml"
OCI_CONFIG_FILE = "oci_config"

# --- OCI client rate limiting / retry configuration ---
_OCI_RATE_LIMIT_PER_SECOND = 1
_OCI_RETRY_MAX_ATTEMPTS = 5
_OCI_RETRY_WAIT_MIN_SECONDS = 2
_OCI_RETRY_WAIT_MAX_SECONDS = 30

if _OCI_RATE_LIMIT_PER_SECOND >= 1:
    _rate = int(_OCI_RATE_LIMIT_PER_SECOND)
    _duration = Duration.SECOND
else:
    _rate = 1
    _duration = int(Duration.SECOND * (1 / _OCI_RATE_LIMIT_PER_SECOND))
_oci_limiter = limiter_factory.create_inmemory_limiter(rate_per_duration=_rate, duration=_duration)


class PortRangeConfig(BaseModel):
    """Configuration for a network port range."""

    min: int
    max: int


class SecurityRuleConfig(BaseModel):
    """Declarative model for ingress firewall configuration."""

    protocol: str  # "6" (TCP), "17" (UDP), "1" (ICMP), "58" (IPv6-ICMP), or "all"
    source: str = "0.0.0.0/0"
    port: Optional[int] = None  # single port helper
    port_range: Optional[PortRangeConfig] = None  # range helper
    description: Optional[str] = None
    is_stateless: bool = False


class ServerConfig(BaseModel):
    """Configuration options for a server instance."""

    name: str
    shape: str
    cpu: int
    ram: int
    swap: int
    disk: int
    ssh_auth_key: str | None = None
    security_rules: List[SecurityRuleConfig] = []  # Per-instance specific rules
    reserved_ip: bool = False  # True if this instance should receive the reserved IP
    cronjobs: List[str] = []  # Custom cronjobs to install on boot


class AccountConfig(BaseModel):
    """Configuration for an OCI account."""

    name: str
    servers: List[ServerConfig]


class DefaultConfig(BaseModel):
    """Global default configurations for servers and security rules."""

    ssh_auth_key: str
    security_rules: List[SecurityRuleConfig] = []  # Global defaults


class Config(BaseModel):
    """Top-level application configuration model."""

    defaults: DefaultConfig
    accounts: List[AccountConfig]

    @model_validator(mode="after")
    def apply_global_defaults(self) -> "Config":
        """Apply global SSH key defaults to server configurations if not set.

        Returns:
            The updated Config instance.
        """
        if not self.defaults.security_rules:
            self.defaults.security_rules = list(DEFAULT_RULES)

        for account in self.accounts:
            for server in account.servers:
                if server.ssh_auth_key is None:
                    server.ssh_auth_key = self.defaults.ssh_auth_key
        return self


def _is_rate_limited(exc: BaseException) -> bool:
    """Check whether an exception represents an OCI 429 TooManyRequests response.

    Args:
        exc: The exception raised by an OCI API call.

    Returns:
        True if the exception is an OCI 429 rate-limit error.
    """
    return isinstance(exc, oci.exceptions.ServiceError) and exc.status == 429


def _rate_limit_and_retry(func):
    """Wrap an OCI client method with shared rate limiting and 429 retry/backoff.

    Args:
        func: The bound OCI client method to wrap.

    Returns:
        A wrapped version of func with rate limiting and 429 retry applied.
    """

    @retry(
        retry=retry_if_exception(_is_rate_limited),
        stop=stop_after_attempt(_OCI_RETRY_MAX_ATTEMPTS),
        wait=wait_exponential(multiplier=1, min=_OCI_RETRY_WAIT_MIN_SECONDS, max=_OCI_RETRY_WAIT_MAX_SECONDS),
        reraise=True,
    )
    def wrapped(*args, **kwargs):
        _oci_limiter.try_acquire("oci")
        return func(*args, **kwargs)

    return wrapped


def apply_rate_limiting(client):
    """Patch every public method on an OCI client with rate limiting and 429 retry.

    Args:
        client: An OCI service client instance (e.g. ComputeClient).

    Returns:
        The same client instance, with its public methods wrapped in place.
    """
    for name in dir(client):
        if name.startswith("_"):
            continue
        attr = getattr(client, name)
        if inspect.ismethod(attr):
            setattr(client, name, _rate_limit_and_retry(attr))
    return client


class AccountSession(BaseModel):
    """Holds OCI client context and account configurations."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    account_name: str

    identity_client: IdentityClient
    compute_client: ComputeClient
    virtual_network_client: VirtualNetworkClient
    block_storage_client: BlockstorageClient
    work_request_client: WorkRequestClient
    compute_client_composite_operations: ComputeClientCompositeOperations
    virtual_network_composite_operations: VirtualNetworkClientCompositeOperations

    compartment_id: str
    subnet_id: Optional[str] = None
    nsg_ids: Dict[str, str] = {}

    @classmethod
    def from_account(cls, account_name: str, oci_config_path: str) -> "AccountSession":
        """Create an AccountSession instance from account name and config path.

        Args:
            account_name: Name of the OCI account profile.
            oci_config_path: Path to the OCI configuration file.

        Returns:
            An initialized AccountSession instance.

        Raises:
            RuntimeError: If tenancy cannot be retrieved from the OCI config.
        """
        config = oci.config.from_file(oci_config_path, account_name)

        identity_client = apply_rate_limiting(oci.identity.IdentityClient(config))
        compute_client = apply_rate_limiting(oci.core.ComputeClient(config))
        virtual_network_client = apply_rate_limiting(oci.core.VirtualNetworkClient(config))
        block_storage_client = apply_rate_limiting(oci.core.BlockstorageClient(config))
        work_request_client = apply_rate_limiting(oci.work_requests.WorkRequestClient(config))
        compute_client_composite_operations = oci.core.ComputeClientCompositeOperations(compute_client)
        virtual_network_composite_operations = oci.core.VirtualNetworkClientCompositeOperations(virtual_network_client)

        compartment_id = config.get("tenancy")
        if not compartment_id:
            raise RuntimeError(f"Cannot get tenancy for {account_name} from {oci_config_path}")

        return cls(
            account_name=account_name,
            identity_client=identity_client,
            compute_client=compute_client,
            virtual_network_client=virtual_network_client,
            block_storage_client=block_storage_client,
            work_request_client=work_request_client,
            compute_client_composite_operations=compute_client_composite_operations,
            virtual_network_composite_operations=virtual_network_composite_operations,
            compartment_id=compartment_id,
        )


def load_config(config_path: str = CONFIG_FILE) -> Config:
    """Load the YAML configuration into Pydantic models.

    Args:
        config_path: Path to the YAML configuration file.

    Returns:
        The loaded Config instance.
    """
    with open(config_path, "r") as f:
        raw_data = safe_load(f)
        config = Config(**raw_data)
        return config


def is_ubuntu_lts(version: str) -> bool:
    """Verify if an OS version string corresponds to an Ubuntu LTS release.

    Args:
        version: Operating system version string.

    Returns:
        True if the version corresponds to an Ubuntu LTS release, False otherwise.
    """
    if not version:
        return False
    parts = version.split()
    if not parts:
        return False
    ver_num = parts[0]
    if ver_num.endswith(".04"):
        try:
            year = int(ver_num.split(".")[0])
            return year % 2 == 0
        except ValueError:
            return False
    return False


def get_latest_ubuntu_lts_image_id(compute_client: ComputeClient, compartment_id: str, shape: str) -> str:
    """Query and filter OCI image catalog to return the newest compatible Ubuntu LTS release.

    Args:
        compute_client: OCI ComputeClient instance.
        compartment_id: OCID of the compartment.
        shape: Compute instance shape.

    Returns:
        The OCID of the latest compatible Ubuntu LTS image.

    Raises:
        RuntimeError: If response is invalid or no compatible image is found.
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            compute_client.list_images,
            compartment_id=compartment_id,
            shape=shape,
            operating_system="Canonical Ubuntu",
        )
        if not isinstance(response, oci.response.Response):
            raise RuntimeError("Invalid response structure returned from list_images.")
        images = response.data
    except Exception as e:
        logfire.warning(f"Direct image listing failed: {e}. Trying broad fallback listing...")
        images = []

    lts_images = [
        img for img in images if is_ubuntu_lts(img.operating_system_version) and img.lifecycle_state == "AVAILABLE"
    ]
    lts_images.sort(key=lambda x: x.time_created, reverse=True)

    if not lts_images:
        all_images_response = oci.pagination.list_call_get_all_results(
            compute_client.list_images,
            compartment_id=compartment_id,
            operating_system="Canonical Ubuntu",
        )
        if not isinstance(all_images_response, oci.response.Response):
            raise RuntimeError("Failed to list standard Canonical Ubuntu images.")
        all_images = all_images_response.data

        compatible_images = []
        for img in all_images:
            if not is_ubuntu_lts(img.operating_system_version) or img.lifecycle_state != "AVAILABLE":
                continue
            try:
                shapes_response = oci.pagination.list_call_get_all_results(
                    compute_client.list_shapes,
                    compartment_id=compartment_id,
                    image_id=img.id,
                )
                if isinstance(shapes_response, oci.response.Response):
                    shapes = shapes_response.data
                    if any(s.shape == shape for s in shapes):
                        compatible_images.append(img)
            except Exception:
                continue

        compatible_images.sort(key=lambda x: x.time_created, reverse=True)
        lts_images = compatible_images

    if not lts_images:
        raise RuntimeError(f"No suitable Canonical Ubuntu LTS image was found for shape {shape}.")

    for img in lts_images:
        display_name = img.display_name.lower()
        if "minimal" not in display_name and "gpu" not in display_name:
            return img.id

    return lts_images[0].id


def get_supported_shapes_by_ad(
    identity_client: IdentityClient,
    compute_client: ComputeClient,
    compartment_id: str,
) -> Dict[str, set]:
    """Query all availability domains in a compartment and return a mapping of AD name to supported shapes.

    Args:
        identity_client: OCI IdentityClient instance.
        compute_client: OCI ComputeClient instance.
        compartment_id: OCID of the compartment.

    Returns:
        A dictionary mapping each Availability Domain name to a set of supported shape names.
    """
    ads_response = identity_client.list_availability_domains(compartment_id=compartment_id)
    if not isinstance(ads_response, oci.response.Response) or not ads_response.data:
        logfire.warning(f"Could not list availability domains for compartment {compartment_id}")
        return {}

    shapes_by_ad: Dict[str, set] = {}
    for ad in ads_response.data:
        shapes_by_ad[ad.name] = set()
        try:
            shapes_response = oci.pagination.list_call_get_all_results(
                compute_client.list_shapes,
                compartment_id=compartment_id,
                availability_domain=ad.name,
            )
            if isinstance(shapes_response, oci.response.Response) and shapes_response.data:
                shapes_by_ad[ad.name] = {s.shape for s in shapes_response.data}
        except Exception as e:
            logfire.warning(f"Failed to list shapes for AD '{ad.name}': {e}")

    debug_payload = {ad_name: sorted(list(shapes)) for ad_name, shapes in shapes_by_ad.items()}
    logfire.debug(
        "Discovered supported shapes per Availability Domain",
        compartment_id=compartment_id,
        shapes_by_ad=debug_payload,
    )

    return shapes_by_ad


def get_availability_domain(
    identity_client: IdentityClient,
    compartment_id: str,
    compute_client: Optional[ComputeClient] = None,
    shape: Optional[str] = None,
    shapes_by_ad: Optional[Dict[str, set]] = None,
) -> str:
    """Retrieve an availability domain for a compartment, optionally filtering by shape support.

    Args:
        identity_client: OCI IdentityClient instance.
        compartment_id: OCID of the compartment.
        compute_client: Optional OCI ComputeClient instance to check shape availability.
        shape: Optional compute shape string to filter availability domains.
        shapes_by_ad: Optional pre-fetched map of AD name to set of supported shapes.

    Returns:
        The name of the availability domain that supports the specified shape or the first available AD.

    Raises:
        RuntimeError: If listing availability domains fails or none are found.
    """
    response = identity_client.list_availability_domains(compartment_id=compartment_id)
    if not isinstance(response, oci.response.Response):
        raise RuntimeError("Failed to retrieve availability domains payload.")
    ads = response.data
    if not ads:
        raise RuntimeError(f"No availability domains found for compartment {compartment_id}")

    if shape:
        if shapes_by_ad:
            for ad in ads:
                if shape in shapes_by_ad.get(ad.name, set()):
                    logfire.info(f"Selected Availability Domain '{ad.name}' matching shape '{shape}'.")
                    return ad.name

        if compute_client:
            for ad in ads:
                try:
                    shapes_response = compute_client.list_shapes(
                        compartment_id=compartment_id, availability_domain=ad.name
                    )
                    if isinstance(shapes_response, oci.response.Response) and shapes_response.data:
                        if any(s.shape == shape for s in shapes_response.data):
                            logfire.info(f"Selected Availability Domain '{ad.name}' matching shape '{shape}'.")
                            return ad.name
                except Exception as e:
                    logfire.warning(f"Could not check shape availability in AD '{ad.name}': {e}")

    return ads[0].name


def merge_server_rules(
    server_config: ServerConfig, global_defaults: List[SecurityRuleConfig]
) -> List[SecurityRuleConfig]:
    """Combine global default ingress configurations with server-specific configurations.

    Args:
        server_config: Server configuration containing per-instance rules.
        global_defaults: List of global default security rules.

    Returns:
        A combined list of security rules.
    """
    rules = list(global_defaults)
    rules.extend(server_config.security_rules)
    return rules


def get_or_create_nsg(
    virtual_network_client: VirtualNetworkClient,
    compartment_id: str,
    vcn_id: str,
    server_name: str,
) -> str:
    """Find an existing Network Security Group for the server or create a new one.

    Args:
        virtual_network_client: OCI VirtualNetworkClient instance.
        compartment_id: OCID of the compartment.
        vcn_id: OCID of the VCN.
        server_name: Name of the server.

    Returns:
        The OCID of the Network Security Group.

    Raises:
        RuntimeError: If listing or creating NSG fails.
    """
    nsg_name = f"{server_name}-nsg"
    nsgs_response = oci.pagination.list_call_get_all_results(
        virtual_network_client.list_network_security_groups,
        compartment_id=compartment_id,
        vcn_id=vcn_id,
    )
    if not isinstance(nsgs_response, oci.response.Response):
        raise RuntimeError("Failed to list Network Security Groups.")

    for nsg in nsgs_response.data:
        if nsg.display_name == nsg_name:
            return nsg.id

    logfire.info(f"Creating dedicated Network Security Group '{nsg_name}'...")
    create_details = oci.core.models.CreateNetworkSecurityGroupDetails(
        compartment_id=compartment_id, vcn_id=vcn_id, display_name=nsg_name
    )
    response = virtual_network_client.create_network_security_group(create_details)
    if not isinstance(response, oci.response.Response):
        raise RuntimeError(f"Failed to create NSG '{nsg_name}'.")
    return response.data.id


def sync_nsg_security_rules(
    virtual_network_client: VirtualNetworkClient,
    nsg_id: str,
    ingress_rules_config: List[SecurityRuleConfig],
):
    """Synchronize rules for the instance NSG by purging obsolete records and re-writing rules.

    Args:
        virtual_network_client: OCI VirtualNetworkClient instance.
        nsg_id: OCID of the Network Security Group.
        ingress_rules_config: List of ingress security rule configurations.

    Raises:
        RuntimeError: If fetching NSG rules fails.
    """
    logfire.info(f"Synchronizing active rules on Network Security Group: {nsg_id}...")

    rules_response = virtual_network_client.list_network_security_group_security_rules(nsg_id)
    if not isinstance(rules_response, oci.response.Response):
        raise RuntimeError(f"Failed to list rules for NSG {nsg_id}")

    existing_rules = rules_response.data
    existing_rule_ids = [r.id for r in existing_rules]

    if existing_rule_ids:
        remove_details = oci.core.models.RemoveNetworkSecurityGroupSecurityRulesDetails(
            security_rule_ids=existing_rule_ids
        )
        virtual_network_client.remove_network_security_group_security_rules(nsg_id, remove_details)

    new_rules = []
    for r in ingress_rules_config:
        tcp_options = None
        udp_options = None

        min_port = None
        max_port = None
        if r.port_range:
            min_port = r.port_range.min
            max_port = r.port_range.max
        elif r.port is not None:
            min_port = r.port
            max_port = r.port

        if min_port is not None and max_port is not None:
            port_range = oci.core.models.PortRange(min=min_port, max=max_port)
            if r.protocol == "6":
                tcp_options = oci.core.models.TcpOptions(destination_port_range=port_range)
            elif r.protocol == "17":
                udp_options = oci.core.models.UdpOptions(destination_port_range=port_range)

        rule_detail = oci.core.models.AddSecurityRuleDetails(
            direction="INGRESS",
            protocol=r.protocol,
            source=r.source,
            source_type="CIDR_BLOCK",
            is_stateless=r.is_stateless,
            description=r.description,
            tcp_options=tcp_options,
            udp_options=udp_options,
        )
        new_rules.append(rule_detail)

    egress_ipv4 = oci.core.models.AddSecurityRuleDetails(
        direction="EGRESS",
        protocol="all",
        destination="0.0.0.0/0",
        destination_type="CIDR_BLOCK",
        description="Allow Outbound IPv4",
    )
    egress_ipv6 = oci.core.models.AddSecurityRuleDetails(
        direction="EGRESS",
        protocol="all",
        destination="::/0",
        destination_type="CIDR_BLOCK",
        description="Allow Outbound IPv6",
    )
    new_rules.extend([egress_ipv4, egress_ipv6])

    if new_rules:
        add_details = oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(security_rules=new_rules)
        virtual_network_client.add_network_security_group_security_rules(nsg_id, add_details)
        logfire.info("NSG security rules successfully synchronized.")


def setup_internet_routing(
    virtual_network_client: VirtualNetworkClient,
    compartment_id: str,
    vcn_id: str,
    subnet,
):
    """Ensure internet gateway exists and route tables contain IPv4 and IPv6 internet routes.

    Args:
        virtual_network_client: OCI VirtualNetworkClient instance.
        compartment_id: OCID of the compartment.
        vcn_id: OCID of the VCN.
        subnet: OCI Subnet object.

    Raises:
        RuntimeError: If internet gateway or route table operations fail.
    """
    igws_response = oci.pagination.list_call_get_all_results(
        virtual_network_client.list_internet_gateways,
        compartment_id=compartment_id,
        vcn_id=vcn_id,
    )
    if not isinstance(igws_response, oci.response.Response):
        raise RuntimeError("Failed to list Internet Gateways.")
    igws = igws_response.data

    if igws:
        igw = igws[0]
    else:
        logfire.info("No Internet Gateway found. Creating Internet Gateway for IPv4/IPv6 routing...")
        create_igw_details = oci.core.models.CreateInternetGatewayDetails(
            compartment_id=compartment_id,
            vcn_id=vcn_id,
            is_enabled=True,
            display_name="InstanceIGW",
        )
        igw_response = virtual_network_client.create_internet_gateway(create_igw_details)
        if not isinstance(igw_response, oci.response.Response):
            raise RuntimeError("Failed to create Internet Gateway payload.")
        igw = igw_response.data

    vcn_response = virtual_network_client.get_vcn(vcn_id)
    if not isinstance(vcn_response, oci.response.Response):
        raise RuntimeError(f"Failed to fetch VCN payload for routing rules sync on VCN ID {vcn_id}")
    vcn_details = vcn_response.data

    rt_response = virtual_network_client.get_route_table(vcn_details.default_route_table_id)
    if not isinstance(rt_response, oci.response.Response):
        raise RuntimeError("Failed to retrieve default Route Table payload.")
    rt = rt_response.data

    route_rules = rt.route_rules or []

    has_ipv4_rule = any(
        (getattr(rule, "destination", None) == "0.0.0.0/0" or getattr(rule, "cidr_block", None) == "0.0.0.0/0")
        for rule in route_rules
    )
    has_ipv6_rule = any(
        (getattr(rule, "destination", None) == "::/0" or getattr(rule, "cidr_block", None) == "::/0")
        for rule in route_rules
    )

    if not has_ipv4_rule:
        route_rules.append(
            oci.core.models.RouteRule(
                destination="0.0.0.0/0",
                destination_type="CIDR_BLOCK",
                network_entity_id=igw.id,
            )
        )
    if not has_ipv6_rule:
        route_rules.append(
            oci.core.models.RouteRule(
                destination="::/0",
                destination_type="CIDR_BLOCK",
                network_entity_id=igw.id,
            )
        )

    if not has_ipv4_rule or not has_ipv6_rule:
        logfire.info("Updating VCN Route Table with standard IPv4/IPv6 destination rules...")
        update_rt_details = oci.core.models.UpdateRouteTableDetails(route_rules=route_rules)
        virtual_network_client.update_route_table(vcn_details.default_route_table_id, update_rt_details)


def get_or_create_ipv6_subnet(
    virtual_network_client: VirtualNetworkClient,
    composite_ops: VirtualNetworkClientCompositeOperations,
    compartment_id: str,
) -> str:
    """Retrieve an existing subnet or create an IPv6-enabled VCN and subnet.

    Args:
        virtual_network_client: OCI VirtualNetworkClient instance.
        composite_ops: Composite operations for VirtualNetworkClient.
        compartment_id: OCID of the compartment.

    Returns:
        The OCID of the IPv6-enabled subnet.

    Raises:
        RuntimeError: If subnet or VCN API operations fail.
    """
    subnets_response = oci.pagination.list_call_get_all_results(
        virtual_network_client.list_subnets, compartment_id=compartment_id
    )
    if not isinstance(subnets_response, oci.response.Response):
        raise RuntimeError("Failed to list existing subnets.")
    subnets = subnets_response.data

    if subnets:
        subnet = subnets[0]
        vcn_response = virtual_network_client.get_vcn(subnet.vcn_id)
        if not isinstance(vcn_response, oci.response.Response):
            raise RuntimeError(f"Failed to fetch VCN payload for VCN ID {subnet.vcn_id}")
        vcn = vcn_response.data

        if not vcn.ipv6_cidr_blocks:
            logfire.info(f"Existing VCN {vcn.id} has IPv6 disabled. Actively enabling IPv6 prefix...")
            composite_ops.add_ipv6_vcn_cidr_and_wait_for_work_request(vcn.id)
            vcn_response = virtual_network_client.get_vcn(subnet.vcn_id)
            if not isinstance(vcn_response, oci.response.Response):
                raise RuntimeError(f"Failed to reload VCN details for VCN ID {subnet.vcn_id}")
            vcn = vcn_response.data

        if not subnet.ipv6_cidr_blocks:
            logfire.info(f"Existing Subnet {subnet.id} has IPv6 disabled. Actively enabling IPv6...")
            vcn_ipv6_prefix = vcn.ipv6_cidr_blocks[0]
            prefix_base = vcn_ipv6_prefix.split("/")[0]
            subnet_ipv6_cidr = f"{prefix_base}/64"

            add_subnet_details = oci.core.models.AddSubnetIpv6CidrDetails(ipv6_cidr_block=subnet_ipv6_cidr)
            composite_ops.add_ipv6_subnet_cidr_and_wait_for_work_request(subnet.id, add_subnet_details)
            subnet_response = virtual_network_client.get_subnet(subnet.id)
            if not isinstance(subnet_response, oci.response.Response):
                raise RuntimeError(f"Failed to reload Subnet details for Subnet ID {subnet.id}")
            subnet = subnet_response.data

        try:
            setup_internet_routing(virtual_network_client, compartment_id, vcn.id, subnet)
        except Exception as e:
            logfire.warning(
                f"Could not automatically initialize gateway routes: {e}. IGW routing may need manual adjustment."
            )

        return subnet.id

    vcns_response = oci.pagination.list_call_get_all_results(
        virtual_network_client.list_vcns, compartment_id=compartment_id
    )
    if not isinstance(vcns_response, oci.response.Response):
        raise RuntimeError("Failed to list existing VCNs.")
    vcns = vcns_response.data

    if vcns:
        vcn = vcns[0]
        if not vcn.ipv6_cidr_blocks:
            logfire.info(f"Enabling IPv6 on VCN {vcn.id}...")
            composite_ops.add_ipv6_vcn_cidr_and_wait_for_work_request(vcn.id)
            vcn_response = virtual_network_client.get_vcn(vcn.id)
            if not isinstance(vcn_response, oci.response.Response):
                raise RuntimeError(f"Failed to reload VCN details for VCN ID {vcn.id}")
            vcn = vcn_response.data
    else:
        logfire.info("No VCN detected in compartment. Creating a new IPv6-enabled VCN...")
        create_vcn_details = oci.core.models.CreateVcnDetails(
            compartment_id=compartment_id,
            cidr_blocks=["10.0.0.0/16"],
            is_ipv6_enabled=True,
            display_name="InstanceVCN",
            dns_label="vcn",
        )
        vcn_response = virtual_network_client.create_vcn(create_vcn_details)
        wait_response = oci.wait_until(
            virtual_network_client,
            virtual_network_client.get_vcn(vcn_response.data.id),
            "lifecycle_state",
            "AVAILABLE",
        )
        if not isinstance(wait_response, oci.response.Response):
            raise RuntimeError("VCN wait_until operation returned a non-response state.")
        vcn = wait_response.data

    logfire.info(f"Creating a new IPv6-enabled Subnet inside VCN {vcn.id}...")
    vcn_ipv6_prefix = vcn.ipv6_cidr_blocks[0]
    prefix_base = vcn_ipv6_prefix.split("/")[0]
    subnet_ipv6_cidr = f"{prefix_base}/64"

    create_subnet_details = oci.core.models.CreateSubnetDetails(
        compartment_id=compartment_id,
        vcn_id=vcn.id,
        cidr_block="10.0.0.0/24",
        ipv6_cidr_blocks=[subnet_ipv6_cidr],
        display_name="InstanceSubnet",
        dns_label="subnet",
    )
    subnet_response = virtual_network_client.create_subnet(create_subnet_details)
    wait_response = oci.wait_until(
        virtual_network_client,
        virtual_network_client.get_subnet(subnet_response.data.id),
        "lifecycle_state",
        "AVAILABLE",
    )
    if not isinstance(wait_response, oci.response.Response):
        raise RuntimeError("Subnet wait_until operation returned a non-response state.")
    subnet = wait_response.data

    try:
        setup_internet_routing(virtual_network_client, compartment_id, vcn.id, subnet)
    except Exception as e:
        logfire.warning(
            f"Could not automatically initialize gateway routes: {e}. IGW routing may need manual adjustment."
        )

    return subnet.id


def get_subnet_id(virtual_network_client: VirtualNetworkClient, compartment_id: str) -> str:
    """Find the first available subnet inside the compartment.

    Args:
        virtual_network_client: OCI VirtualNetworkClient instance.
        compartment_id: OCID of the compartment.

    Returns:
        The OCID of the first available subnet.

    Raises:
        RuntimeError: If listing subnets fails or no subnets are found.
    """
    subnets_response = oci.pagination.list_call_get_all_results(
        virtual_network_client.list_subnets, compartment_id=compartment_id
    )
    if not isinstance(subnets_response, oci.response.Response):
        raise RuntimeError("Failed to list subnets.")
    subnets = subnets_response.data
    if not subnets:
        raise RuntimeError("No subnets found. Ensure you have created a VCN and subnet first.")
    return subnets[0].id


def get_primary_vnic_id_with_retry(
    compute_client: ComputeClient, compartment_id: str, instance_id: str, max_retries: int = 10
) -> str:
    """Poll the API until the primary VNIC attachment is created and return its ID.

    Args:
        compute_client: OCI ComputeClient instance.
        compartment_id: OCID of the compartment.
        instance_id: OCID of the compute instance.
        max_retries: Maximum number of retry attempts.

    Returns:
        The OCID of the primary VNIC attachment.

    Raises:
        RuntimeError: If primary VNIC attachment is not populated within retry limit.
    """
    for attempt in range(max_retries):
        attachments_response = oci.pagination.list_call_get_all_results(
            compute_client.list_vnic_attachments,
            compartment_id=compartment_id,
            instance_id=instance_id,
        )
        if isinstance(attachments_response, oci.response.Response):
            attachments = attachments_response.data
            if attachments:
                return attachments[0].vnic_id
        time.sleep(2)
    raise RuntimeError(f"Primary VNIC attachment did not populate for instance {instance_id}")


def allocate_maximum_ipv6_addresses(
    virtual_network_client: VirtualNetworkClient, vnic_id: str, max_total_count: int = 32
):
    """Audit existing IPv6 addresses and top them up to max_total_count with request throttling.

    Args:
        virtual_network_client: OCI VirtualNetworkClient instance.
        vnic_id: OCID of the VNIC.
        max_total_count: Target total number of IPv6 addresses to allocate.

    Raises:
        RuntimeError: If listing existing IPv6 addresses fails.
    """
    try:
        ipv6s_response = virtual_network_client.list_ipv6s(vnic_id=vnic_id)
        if not isinstance(ipv6s_response, oci.response.Response):
            raise RuntimeError("Failed to list existing IPv6 addresses.")

        existing_count = len(ipv6s_response.data)
        logfire.info(f"VNIC {vnic_id} currently has {existing_count} total IPv6 addresses allocated.")
    except Exception as e:
        logfire.warning(f"Could not audit existing IPv6 addresses: {e}. Defaulting current count to 0.")
        existing_count = 0

    needed_count = max_total_count - existing_count
    if needed_count <= 0:
        logfire.info(f"VNIC {vnic_id} already has the maximum requested {max_total_count} total IPv6 addresses.")
        return

    logfire.info(f"Self-Healing: Need to allocate {needed_count} additional IPv6 addresses to VNIC {vnic_id}...")

    allocated = 0
    for i in range(needed_count):
        try:
            create_details = oci.core.models.CreateIpv6Details(
                vnic_id=vnic_id,
                display_name=f"IPv6-Block-{existing_count + allocated + 1}",
            )
            virtual_network_client.create_ipv6(create_details)
            allocated += 1
        except oci.exceptions.ServiceError as e:
            logfire.info(f"Assigned {allocated} secondary IPv6 addresses. Subnet limit or quota reached: {e.message}")
            break
        except Exception as e:
            logfire.warning(f"Unexpected error allocating secondary IPv6: {e}")
            break
    logfire.info(f"Completed block allocation. Total assigned IPv6 addresses on VNIC: {existing_count + allocated}")


def get_instance_ips_and_nsgs(
    compute_client: ComputeClient,
    virtual_network_client: VirtualNetworkClient,
    compartment_id: str,
    instance_id: str,
) -> tuple[List[str], List[str], List[str], str]:
    """Retrieve lists of IPv4, IPv6, Network Security Group IDs, and the public IPv4 allocation type.

    Args:
        compute_client: OCI ComputeClient instance.
        virtual_network_client: OCI VirtualNetworkClient instance.
        compartment_id: OCID of the compartment.
        instance_id: OCID of the compute instance.

    Returns:
        A tuple containing IPv4 list, IPv6 list, NSG IDs list, and IPv4 lifetime type.

    Raises:
        ServiceError: If an OCI API call fails with a non-404 status code.
    """
    ipv4_addresses = []
    ipv6_addresses = []
    nsg_ids = []
    ipv4_type = "None"
    try:
        attachments_response = oci.pagination.list_call_get_all_results(
            compute_client.list_vnic_attachments,
            compartment_id=compartment_id,
            instance_id=instance_id,
        )
        if isinstance(attachments_response, oci.response.Response):
            for attachment in attachments_response.data:
                vnic_response = virtual_network_client.get_vnic(attachment.vnic_id)
                if isinstance(vnic_response, oci.response.Response):
                    vnic = vnic_response.data
                    if vnic.public_ip:
                        ipv4_addresses.append(vnic.public_ip)

                    if vnic.nsg_ids:
                        nsg_ids.extend(vnic.nsg_ids)

                    ipv6s_response = virtual_network_client.list_ipv6s(vnic_id=attachment.vnic_id)
                    if isinstance(ipv6s_response, oci.response.Response):
                        for ipv6 in ipv6s_response.data:
                            ipv6_addresses.append(ipv6.ip_address)

                    private_ips_response = virtual_network_client.list_private_ips(vnic_id=attachment.vnic_id)
                    if isinstance(private_ips_response, oci.response.Response) and private_ips_response.data:
                        primary_private_ip_id = private_ips_response.data[0].id
                        try:
                            details = oci.core.models.GetPublicIpByPrivateIpIdDetails(
                                private_ip_id=primary_private_ip_id
                            )
                            public_ip_response = virtual_network_client.get_public_ip_by_private_ip_id(details)
                            if isinstance(public_ip_response, oci.response.Response):
                                ipv4_type = public_ip_response.data.lifetime
                        except oci.exceptions.ServiceError as se:
                            if se.status != 404:
                                raise
    except Exception as e:
        logfire.warning(f"Failed to fetch IP addresses or NSG bindings for instance {instance_id}: {e}")
    return ipv4_addresses, ipv6_addresses, list(set(nsg_ids)), ipv4_type


def get_instance_boot_volume_size(
    compute_client: ComputeClient,
    block_storage_client: BlockstorageClient,
    compartment_id: str,
    instance_id: str,
    availability_domain: str,
) -> str:
    """Retrieve the size of the boot volume attached to the instance in GBs.

    Args:
        compute_client: OCI ComputeClient instance.
        block_storage_client: OCI BlockstorageClient instance.
        compartment_id: OCID of the compartment.
        instance_id: OCID of the compute instance.
        availability_domain: Name of the availability domain.

    Returns:
        Boot volume size as a string in GBs, or 'N/A' if unavailable.
    """
    try:
        attachments_response = compute_client.list_boot_volume_attachments(
            availability_domain=availability_domain,
            compartment_id=compartment_id,
            instance_id=instance_id,
        )
        if isinstance(attachments_response, oci.response.Response) and attachments_response.data:
            bv_id = attachments_response.data[0].boot_volume_id
            bv_response = block_storage_client.get_boot_volume(bv_id)
            if isinstance(bv_response, oci.response.Response):
                return f"{int(bv_response.data.size_in_gbs)}"
    except Exception as e:
        logfire.warning(f"Could not retrieve boot volume size for instance {instance_id}: {e}")
    return "N/A"


def get_primary_private_ip_id(virtual_network_client: VirtualNetworkClient, vnic_id: str) -> str:
    """Retrieve the primary private IP ID associated with the primary VNIC.

    Args:
        virtual_network_client: OCI VirtualNetworkClient instance.
        vnic_id: OCID of the VNIC.

    Returns:
        The OCID of the primary private IP.

    Raises:
        RuntimeError: If no private IPs are found on the VNIC.
    """
    response = virtual_network_client.list_private_ips(vnic_id=vnic_id)
    if not isinstance(response, oci.response.Response) or not response.data:
        raise RuntimeError(f"No private IPs found on VNIC {vnic_id}")
    return response.data[0].id


def get_or_create_reserved_public_ip(virtual_network_client: VirtualNetworkClient, compartment_id: str) -> str:
    """Query for an available reserved public IP, or create one if none are available.

    Args:
        virtual_network_client: OCI VirtualNetworkClient instance.
        compartment_id: OCID of the compartment.

    Returns:
        The OCID of the reserved public IP.

    Raises:
        RuntimeError: If public IP creation or waiting fails.
    """
    public_ips_response = oci.pagination.list_call_get_all_results(
        virtual_network_client.list_public_ips,
        scope="REGION",
        compartment_id=compartment_id,
    )
    if isinstance(public_ips_response, oci.response.Response):
        for ip in public_ips_response.data:
            if ip.lifetime == "RESERVED" and ip.lifecycle_state == "AVAILABLE":
                logfire.info(f"Found available reserved public IP: {ip.ip_address} (ID: {ip.id})")
                return ip.id

    logfire.info("No available reserved public IP found. Attempting to create a new reserved public IP...")
    create_details = oci.core.models.CreatePublicIpDetails(
        compartment_id=compartment_id,
        display_name="InstanceReservedIP",
        lifetime="RESERVED",
    )
    response = virtual_network_client.create_public_ip(create_details)
    if not isinstance(response, oci.response.Response):
        raise RuntimeError("Failed to create reserved public IP.")

    wait_response = oci.wait_until(
        virtual_network_client,
        virtual_network_client.get_public_ip(response.data.id),
        "lifecycle_state",
        "AVAILABLE",
    )
    if not isinstance(wait_response, oci.response.Response):
        raise RuntimeError("Failed waiting for created reserved public IP to become available.")
    return wait_response.data.id


def assign_reserved_public_ip(virtual_network_client: VirtualNetworkClient, public_ip_id: str, private_ip_id: str):
    """Bind a reserved public IP to a primary private IP.

    Args:
        virtual_network_client: OCI VirtualNetworkClient instance.
        public_ip_id: OCID of the reserved public IP.
        private_ip_id: OCID of the primary private IP.

    Raises:
        RuntimeError: If assigning reserved public IP fails.
    """
    logfire.info(f"Assigning reserved public IP {public_ip_id} to private IP {private_ip_id}...")
    update_details = oci.core.models.UpdatePublicIpDetails(private_ip_id=private_ip_id)
    response = virtual_network_client.update_public_ip(public_ip_id, update_details)
    if not isinstance(response, oci.response.Response):
        raise RuntimeError("Failed to assign reserved public IP.")

    wait_response = oci.wait_until(
        virtual_network_client,
        virtual_network_client.get_public_ip(public_ip_id),
        "lifecycle_state",
        "ASSIGNED",
    )
    if not isinstance(wait_response, oci.response.Response):
        raise RuntimeError("Failed waiting for reserved public IP assignment.")
    logfire.info("Reserved public IP assigned successfully.")


def ensure_reserved_public_ip(
    virtual_network_client: VirtualNetworkClient,
    compartment_id: str,
    private_ip_id: str,
):
    """Verify IP bindings and swap ephemeral IPv4 with a reserved IPv4 if needed.

    Args:
        virtual_network_client: OCI VirtualNetworkClient instance.
        compartment_id: OCID of the compartment.
        private_ip_id: OCID of the primary private IP.

    Raises:
        ServiceError: If an OCI API call fails with a non-404 status code.
    """
    try:
        details = oci.core.models.GetPublicIpByPrivateIpIdDetails(private_ip_id=private_ip_id)
        response = virtual_network_client.get_public_ip_by_private_ip_id(details)
        if isinstance(response, oci.response.Response):
            current_ip = response.data
            if current_ip.lifetime == "RESERVED":
                logfire.info(
                    f"Instance private IP {private_ip_id} is already correctly associated with "
                    f"reserved public IP: {current_ip.ip_address}"
                )
                return
            elif current_ip.lifetime == "EPHEMERAL":
                logfire.info(
                    f"Instance private IP currently has ephemeral public IP {current_ip.ip_address}. "
                    "Dissociating to allocate reserved IP..."
                )
                virtual_network_client.delete_public_ip(current_ip.id)
                oci.wait_until(
                    virtual_network_client,
                    virtual_network_client.get_public_ip(current_ip.id),
                    "lifecycle_state",
                    "TERMINATED",
                    succeed_on_not_found=True,
                )
    except oci.exceptions.ServiceError as e:
        if e.status != 404:
            raise

    public_ip_id = get_or_create_reserved_public_ip(virtual_network_client, compartment_id)
    assign_reserved_public_ip(virtual_network_client, public_ip_id, private_ip_id)


def log_detailed_service_error(e: oci.exceptions.ServiceError, resource_name: str, action: str):
    """Output a comprehensive debug block detailing the ServiceError from OCI.

    Args:
        e: The OCI ServiceError exception.
        resource_name: Name of the resource being acted upon.
        action: Description of the action attempted.
    """
    logfire.error(
        f"OCI API Error during '{action}' on resource '{resource_name}':\n"
        f"  - HTTP Status: {e.status}\n"
        f"  - OCI Error Code: {e.code}\n"
        f"  - Error Message: {e.message}\n"
        f"  - OPC Request ID: {getattr(e, 'request_id', 'Unknown')}\n"
        f"  - Target Service: {getattr(e, 'target_service', 'Unknown')}"
    )


DEFAULT_RULES = [
    SecurityRuleConfig(protocol="6", source="0.0.0.0/0", port=22, description="Default: Allow SSH IPv4"),
    SecurityRuleConfig(protocol="6", source="::/0", port=22, description="Default: Allow SSH IPv6"),
    SecurityRuleConfig(protocol="1", source="0.0.0.0/0", description="Default: Allow ICMPv4"),
    SecurityRuleConfig(protocol="58", source="::/0", description="Default: Allow ICMPv6"),
]
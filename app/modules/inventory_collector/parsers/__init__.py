from .huawei        import parse_huawei
from .cisco         import parse_cisco, parse_cisco_ap, _is_cisco_ap
from .dell_force10  import parse_dell_force10
from .hp_comware    import parse_hp_comware
from .fortigate     import parse_fortigate
from .fortinet_ssh  import parse_fortinet_ssh
from .f5            import parse_f5
from .extreme       import parse_extreme
from .ruijie        import parse_ruijie


def get_parser(device_type: str):
    dt = device_type.lower()

    if "huawei" in dt:
        return parse_huawei
    if "cisco_ap" in dt or "aironet" in dt or "lwap" in dt:
        return parse_cisco_ap
    if "cisco" in dt:
        return parse_cisco
    if "dell_force10" in dt or "dell" in dt:
        return parse_dell_force10
    if "h3c_comware" in dt or "hp_comware" in dt or "comware" in dt or "h3c" in dt or "hp_procurve" in dt:
        return parse_hp_comware
    if "extreme_exos" in dt or "extreme" in dt:
        return parse_extreme
    if "ruijie_os" in dt or "ruijie" in dt or "rgos" in dt:
        return parse_ruijie
    if "fortigate" in dt or (
        "fortinet" in dt
        and "fortianalyz" not in dt
        and "fortimanag" not in dt
    ):
        return parse_fortigate
    if any(t in dt for t in ("fortianalyzer", "fortimanager", "fortiauthenticator",
                              "fortisandbox", "forticlientems", "fortiems")):
        return parse_fortinet_ssh
    if "bigip" in dt or "f5" in dt or "big-ip" in dt:
        return parse_f5

    return None
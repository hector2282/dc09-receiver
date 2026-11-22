"""Event code tables for Contact ID (ADM-CID) and SIA DCS.

Each entry maps a code to ``(category, english, spanish)``. Categories:

* ``alarm``       - burglary, fire, panic, duress, medical ... (wake someone up)
* ``trouble``     - tamper, AC loss, low battery, communication failure
* ``supervisory`` - bypass, programming, access denied
* ``openclose``   - arming / disarming
* ``test``        - manual and periodic tests
* ``info``        - everything else

Codes that are not in the table are still delivered, with category ``info``
and a generic description, so nothing is silently dropped.
"""

from __future__ import annotations

__all__ = ["CID", "SIA", "describe_cid", "describe_sia"]

Entry = tuple[str, str, str]

CID: dict[str, Entry] = {
    "100": ("alarm", "Medical emergency", "Emergencia médica"),
    "101": ("alarm", "Personal emergency pendant", "Pulsador de emergencia personal"),
    "110": ("alarm", "Fire alarm", "Alarma de incendio"),
    "111": ("alarm", "Smoke", "Humo"),
    "113": ("alarm", "Water flow", "Flujo de agua"),
    "114": ("alarm", "Heat", "Calor"),
    "117": ("alarm", "Flame", "Llama"),
    "120": ("alarm", "Panic", "Pánico"),
    "121": ("alarm", "Duress", "Coacción"),
    "122": ("alarm", "Silent panic", "Pánico silencioso"),
    "123": ("alarm", "Audible panic", "Pánico audible"),
    "130": ("alarm", "Burglary", "Robo"),
    "131": ("alarm", "Perimeter burglary", "Robo perimetral"),
    "132": ("alarm", "Interior burglary", "Robo interior"),
    "133": ("alarm", "24-hour burglary", "Robo zona 24 h"),
    "134": ("alarm", "Entry/exit burglary", "Robo entrada/salida"),
    "135": ("alarm", "Day/night burglary", "Robo día/noche"),
    "137": ("trouble", "Tamper", "Sabotaje (tamper)"),
    "139": ("alarm", "Verified intrusion", "Intrusión verificada"),
    "140": ("alarm", "General alarm", "Alarma general"),
    "143": ("trouble", "Expansion module failure", "Falla de módulo de expansión"),
    "144": ("trouble", "Sensor tamper", "Sabotaje de sensor"),
    "145": ("trouble", "Expansion module tamper", "Sabotaje de módulo de expansión"),
    "150": ("alarm", "24-hour non-burglary", "Zona 24 h (no robo)"),
    "151": ("alarm", "Gas detected", "Gas detectado"),
    "154": ("alarm", "Water leakage", "Fuga de agua"),
    "158": ("alarm", "High temperature", "Temperatura alta"),
    "159": ("alarm", "Low temperature", "Temperatura baja"),
    "162": ("alarm", "Carbon monoxide", "Monóxido de carbono"),
    "300": ("trouble", "System trouble", "Problema del sistema"),
    "301": ("trouble", "AC power loss", "Falla de energía AC"),
    "302": ("trouble", "Low system battery", "Batería baja del sistema"),
    "305": ("info", "System reset", "Reinicio del sistema"),
    "306": ("supervisory", "Programming changed", "Programación modificada"),
    "309": ("trouble", "Battery test failure", "Falla en prueba de batería"),
    "311": ("trouble", "Battery missing", "Batería ausente"),
    "321": ("trouble", "Bell/siren trouble", "Falla de sirena"),
    "344": ("trouble", "RF jamming detected", "Interferencia de RF (jamming)"),
    "350": ("trouble", "Communication trouble", "Falla de comunicación"),
    "351": ("trouble", "Telco line 1 fault", "Falla de línea telefónica 1"),
    "352": ("trouble", "Telco line 2 fault", "Falla de vía de comunicación 2"),
    "353": ("trouble", "Long-range radio fault", "Falla del transmisor de largo alcance"),
    "354": ("trouble", "Failure to communicate event", "No pudo comunicar un evento"),
    "373": ("trouble", "Fire loop trouble", "Falla de lazo de incendio"),
    "374": ("trouble", "Exit error alarm", "Error de salida"),
    "380": ("trouble", "Sensor trouble", "Falla de sensor"),
    "381": ("trouble", "Loss of RF supervision", "Pérdida de supervisión RF"),
    "383": ("trouble", "Sensor tamper", "Sabotaje de sensor"),
    "384": ("trouble", "RF low battery", "Batería baja de sensor inalámbrico"),
    "400": ("openclose", "Open/close", "Apertura/cierre"),
    "401": ("openclose", "Open/close by user", "Apertura/cierre por usuario"),
    "402": ("openclose", "Group open/close", "Apertura/cierre por grupo"),
    "403": ("openclose", "Automatic open/close", "Apertura/cierre automático"),
    "406": ("openclose", "Cancel", "Cancelación"),
    "407": ("openclose", "Remote arm/disarm", "Armado/desarmado remoto"),
    "408": ("openclose", "Quick arm", "Armado rápido"),
    "409": ("openclose", "Keyswitch open/close", "Apertura/cierre por llave"),
    "411": ("info", "Callback request", "Solicitud de devolución de llamada"),
    "412": ("info", "Successful download", "Descarga exitosa"),
    "421": ("supervisory", "Access denied", "Acceso denegado"),
    "422": ("info", "Access granted", "Acceso concedido"),
    "441": ("openclose", "Armed stay", "Armado en casa"),
    "442": ("openclose", "Keyswitch armed stay", "Armado en casa por llave"),
    "454": ("trouble", "Failed to close", "No se armó a tiempo"),
    "456": ("openclose", "Partial arm", "Armado parcial"),
    "459": ("trouble", "Recent close", "Cierre reciente"),
    "570": ("supervisory", "Zone bypass", "Zona anulada"),
    "571": ("supervisory", "Fire zone bypass", "Zona de incendio anulada"),
    "573": ("supervisory", "24-hour zone bypass", "Zona 24 h anulada"),
    "601": ("test", "Manual test", "Prueba manual"),
    "602": ("test", "Periodic test", "Prueba periódica"),
    "603": ("test", "Periodic RF test", "Prueba periódica RF"),
    "604": ("test", "Fire test", "Prueba de incendio"),
    "607": ("test", "Walk test mode", "Modo prueba de paso"),
    "608": ("trouble", "Periodic test with trouble", "Prueba periódica con problema"),
    "611": ("test", "Point tested OK", "Punto probado OK"),
    "623": ("info", "Event log 90% full", "Registro de eventos casi lleno"),
    "625": ("info", "Time/date reset", "Fecha y hora reajustadas"),
    "627": ("supervisory", "Program mode entry", "Entró a programación"),
    "628": ("info", "Program mode exit", "Salió de programación"),
}

SIA: dict[str, Entry] = {
    "BA": ("alarm", "Burglary alarm", "Alarma de robo"),
    "BR": ("info", "Burglary restoral", "Robo restaurado"),
    "BB": ("supervisory", "Burglary bypass", "Zona de robo anulada"),
    "BU": ("supervisory", "Burglary unbypass", "Zona de robo habilitada"),
    "BT": ("trouble", "Burglary trouble", "Falla en zona de robo"),
    "BJ": ("info", "Burglary trouble restoral", "Falla de zona de robo restaurada"),
    "BC": ("openclose", "Burglary cancel", "Cancelación de robo"),
    "BV": ("alarm", "Burglary verified", "Robo verificado"),
    "FA": ("alarm", "Fire alarm", "Alarma de incendio"),
    "FR": ("info", "Fire restoral", "Incendio restaurado"),
    "FT": ("trouble", "Fire trouble", "Falla en zona de incendio"),
    "FB": ("supervisory", "Fire bypass", "Zona de incendio anulada"),
    "PA": ("alarm", "Panic alarm", "Pánico"),
    "PR": ("info", "Panic restoral", "Pánico restaurado"),
    "HA": ("alarm", "Holdup alarm", "Asalto"),
    "HR": ("info", "Holdup restoral", "Asalto restaurado"),
    "MA": ("alarm", "Medical alarm", "Emergencia médica"),
    "MR": ("info", "Medical restoral", "Emergencia médica restaurada"),
    "QA": ("alarm", "Emergency alarm", "Emergencia"),
    "GA": ("alarm", "Gas alarm", "Gas"),
    "WA": ("alarm", "Water alarm", "Agua"),
    "KA": ("alarm", "Heat alarm", "Calor"),
    "TA": ("trouble", "Tamper alarm", "Sabotaje (tamper)"),
    "TR": ("info", "Tamper restoral", "Sabotaje restaurado"),
    "UA": ("alarm", "Untyped zone alarm", "Alarma sin tipo"),
    "UR": ("info", "Untyped zone restoral", "Alarma sin tipo restaurada"),
    "AT": ("trouble", "AC trouble", "Falla de energía AC"),
    "AR": ("info", "AC restoral", "Energía AC restaurada"),
    "YT": ("trouble", "System battery trouble", "Batería baja del sistema"),
    "YR": ("info", "System battery restoral", "Batería del sistema restaurada"),
    "YM": ("trouble", "System battery missing", "Batería ausente"),
    "YP": ("trouble", "Power supply trouble", "Falla de fuente"),
    "YC": ("trouble", "Communications fail", "Falla de comunicación"),
    "YK": ("info", "Communications restoral", "Comunicación restaurada"),
    "XT": ("trouble", "Transmitter battery trouble", "Batería baja de sensor inalámbrico"),
    "XR": ("info", "Transmitter battery restoral", "Batería de sensor restaurada"),
    "XQ": ("trouble", "RF interference", "Interferencia de RF"),
    "US": ("trouble", "Untyped supervision loss", "Pérdida de supervisión"),
    "OP": ("openclose", "Opening (disarm)", "Desarmado"),
    "CL": ("openclose", "Closing (arm)", "Armado"),
    "OG": ("openclose", "Group opening", "Desarmado por grupo"),
    "CG": ("openclose", "Group closing", "Armado por grupo"),
    "OA": ("openclose", "Automatic opening", "Desarmado automático"),
    "CA": ("openclose", "Automatic closing", "Armado automático"),
    "CP": ("openclose", "Automatic closing", "Armado automático"),
    "OR": ("openclose", "Disarm from alarm", "Desarmado tras alarma"),
    "CR": ("trouble", "Recent closing", "Cierre reciente"),
    "OS": ("openclose", "Keyswitch opening", "Desarmado por llave"),
    "CS": ("openclose", "Keyswitch closing", "Armado por llave"),
    "NL": ("openclose", "Perimeter armed (stay)", "Armado en casa"),
    "JA": ("supervisory", "User code tamper", "Intentos de clave inválida"),
    "DD": ("supervisory", "Access denied", "Acceso denegado"),
    "DG": ("info", "Access granted", "Acceso concedido"),
    "RP": ("test", "Automatic test", "Prueba periódica"),
    "RX": ("test", "Manual test", "Prueba manual"),
    "RY": ("test", "Test off-normal", "Prueba con anomalía"),
    "RR": ("info", "Power up", "Encendido del sistema"),
    "LB": ("supervisory", "Local program", "Entró a programación local"),
    "LX": ("info", "Local programming ended", "Salió de programación local"),
    "ZB": ("supervisory", "Zone bypass", "Zona anulada"),
    "ZU": ("supervisory", "Zone unbypass", "Zona habilitada"),
}

# Contact ID open/close codes: the qualifier means 1 = disarm (open) and
# 3 = arm (close). Everywhere else 3 means "restore". Getting this wrong
# makes a whole shift read backwards.
CID_OPEN_CLOSE = frozenset({"400", "401", "402", "403", "406", "407", "408", "409", "441", "442", "456"})
CID_STAY = frozenset({"441", "442", "456"})

SIA_ARMED_AWAY = frozenset({"CL", "CG", "CA", "CP", "CS", "CI", "CJ", "CQ"})
SIA_ARMED_STAY = frozenset({"NL", "CF", "CD"})
SIA_DISARMED = frozenset({"OP", "OG", "OA", "OR", "OS", "OI", "OJ", "OK", "OQ"})

# Supervision heartbeats: they prove the link is alive and nothing else.
CID_PERIODIC = frozenset({"602", "603"})
SIA_PERIODIC = frozenset({"RP"})


def _pick(entry: Entry, lang: str) -> tuple[str, str]:
    category, en, es = entry
    return category, (es if lang == "es" else en)


def describe_cid(code: str, qualifier: str, lang: str = "en") -> tuple[str, str]:
    """Return ``(category, description)`` for a 3-digit Contact ID code."""
    entry = CID.get(code)
    if entry is None:
        return "info", (f"Evento Contact ID {code}" if lang == "es" else f"Contact ID event {code}")
    category, text = _pick(entry, lang)
    if code in CID_OPEN_CLOSE:
        if lang == "es":
            verb = "Desarmado" if qualifier == "1" else "Armado"
        else:
            verb = "Disarmed" if qualifier == "1" else "Armed"
        return category, f"{verb}: {text}"
    if qualifier == "3" and category != "test":
        prefix = "Restaurado" if lang == "es" else "Restore"
        return "info", f"{prefix}: {text}"
    return category, text


def describe_sia(code: str, lang: str = "en") -> tuple[str, str]:
    entry = SIA.get(code)
    if entry is None:
        return "info", (f"Evento SIA {code}" if lang == "es" else f"SIA event {code}")
    return _pick(entry, lang)

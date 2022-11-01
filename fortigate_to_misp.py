# module import

# standard library
import os
import time
import traceback
import pathlib
import sys
import datetime
from typing import Union, List, Dict

# pip install module
from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute

# custom module
import const
from mailsender import MailSender

# suppress secureWarning
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

# Functions:


def check_const(constant_data: Union[str, int, pathlib.Path], constant_name: str) -> bool:
    """ Checks if the constant value is set to a valid value.
    Args:
        constant_data (Union[str, int, pathlib.Path]): constant value that was set in const.py
        constant_name (str): Constant name of the corresponding constant (used when outputting an error message)
    Returns:
        bool: True if valid, False if invalid
    """
    # define the error message as it is common
    error_msg = f"const.py: No value set for {constant_name}. Set the correct value and try again. "
    # None is an error
    if constant_data is None:
        print(error_msg)
        return False
    # Space is an error in string (str)
    if isinstance(constant_data, str) and constant_data == "":
        print(error_msg)
        return False
    # error if the number is negative
    if isinstance(constant_data, int) and constant_data < 0:
        print(error_msg)
        return False
    # In the case of pathlib, it is OK if the file name is set for the time being (check separately whether it can be written or not according to the requirements of the usage location)
    if isinstance(constant_data, pathlib.Path) and constant_data.name == "":
        print(error_msg)
        return False
    # Judged as normal if none of the conditions match
    return True


def get_dir() -> str:
    """ Get the log directory
    Returns:
        str: log directory path
    """
    #
    dir = const.LOG_DIR
    # Remove if the last is /
    return dir[0:-1] if dir.endswith("/") else dir


def get_event(d: dict) -> MISPEvent:
    """ Get the MISPEvent
    Args:
        d (dict): key/value format dict
    Returns:
        MISPEvent: MISPEvent object
    """

    # search for label and return None if not in constant
    logid = d["logid"]
    message_id = logid[4:]
    label = const.MESSAGE_ID_LABEL.get(message_id, None)
    # Replace label if there is anything to change in the modifier's label
    for m in const.MODIFIERS:
        l = m.modify_label(message_id, d)
        if l is not None:
            label = l
    if label is None:
        return None

    # add event tag
    event_tags = ["fortigate"]
    for key in const.TAG_KEYS:
        event_tags.append(f"fortigate:{key}:{d[key]}")

    # add attributes
    attrs = []
    # datetime
    datetime = f"{d['date']}T{d['time']}{d['tz']}"
    datetime_attr = get_attr("Other", "datetime", datetime, "",
        ["fortigate:date", "fortigate:time", "fortigate:tz"], True)
    attrs.append(datetime_attr)

    # ip|port
    # Payload delivery for Anti Virus, Network activity otherwise
    c = "Payload delivery" if message_id in const.MESSAGE_ID_AV else "Network activity"
    for (key_ip, key_port, t) in [("srcip", "srcport", "ip-src|port"), ("dstip", "dstport", "ip-dst|port")]:
        (ip, port) = (d.get(key_ip), d.get(key_port))
        if ip and port:
            attrs.append(get_attr(c, t, f"{ip}|{port}", "", [
                         f"fortigate:{key_ip}", f"fortigate:{key_port}"], False))
    # Create the content of key as attribute
    for k, v in d.items():
        if k in const.IGNORE_KEYS:
            continue
        c, t = const.KEY_CATEGORY_TYPE.get(k, const.OTHER_CATEGORY_TYPE)
        disable_correlation = c in const.DISABLE_CORRELATION_CATEGORY
        attrs.append(
            get_attr(c, t, v, "", [f"fortigate:{k}"], disable_correlation))

    # create event
    event = MISPEvent()
    event.from_dict(
        distribution=const.MISP_DISTRIBUTION,
        threat_level_id=const.MISP_THREAT_LEVEL_ID,
        analysis=const.MISP_ANALYSIS,
        info=f"[FortiGate] {datetime} {label}",
        date=datetime,
        published=True,
        sharing_group_id=None,
        Tag=get_tag(event_tags),
        Attribute=attrs,
    )
    return event


def get_attr(category: str, _type: str, value: str, comment: str, tags: list = [], disable_correlation: bool = False) -> dict:
    """ Get the Attribute format used for MISPEvent
    Args:
        category (str): MISP category
        _type (str): MISP type
        value (str): value
        comment (str): comment
        tags (list, optional): tag list. Defaults to [].
        disable_correlation (bool, optional): disable correlation. Defaults to False.
    Returns:
        dict: _description_
    """
    return {
        "category": category,
        "type": _type,
        "value": value,
        "comment": comment,
        "disable_correlation": disable_correlation,
        "Tag": get_tag(tags)
    }


def get_tag(tags: list) -> list:
    """ Get the Tag format used for MISPEvent
    Args:
        tags (list): list of tag names
    Returns:
        list: Tag format used for MISPEvent
    """
    t = []
    for tag in tags:
        t.append({"name": tag})
    return t


def register_misp(misp: ExpandedPyMISP, event: MISPEvent) -> None:
    """ Receive MISP event data and register with MISP
    Args:
        misp (ExpandedPyMISP): ExpandedPyMISP with registration available
        event (MISPEvent): MISP event to register
    Raises:
        Exception: registration failed
    """
    retry_count = 0
    while True:
        try:
            # Instantiate pymisp and register for events
            event_data = misp.add_event(event)
            if event_data.get("errors"):
                raise Exception(event_data["errors"])

            # Get the event ID registered in MISP and output
            event_id = event_data["Event"]["id"]
            print(f"Newly registered Event_ID: {event_id}")

            return

        except Exception:
            except_return = traceback.format_exc()

            # if already imported
            if const. DUPLICATE_EVENT_CONFIRM_WORD in except_return:
                print("The event you tried to import is already registered in MISP")
                return

            # check retry count
            retry_count += 1
            if retry_count >= const.RETRY_MAXIMUM_LIMIT:
                raise

            # interval processing
            print("Retry event import to MISP")
            time.sleep(const.COMMAND_INTERVAL_TIME)


def mail_send(mail_buffer: list) -> None:
    """ Send an email
    Args:
        mail_buffer (list): list of strings in the email body
    """
    print("Contents sent by email:")
    body = "\n".join(mail_buffer)
    print(body)

    if const.MAIL_TO is None or const.MAIL_TO == "":
        print("Email will not be sent because the destination has not been set.")
        return

    sender = MailSender(
        from_address=const.MAIL_FROM,
        smtp_server=const.MAIL_SMTP_SERVER,
        smtp_user=const.MAIL_SMTP_USER,
        smtp_password=const.MAIL_SMTP_PASSWORD)

    sender.send(const.MAIL_TO, mail_subject, body)


def line_to_dict(line: str) -> dict:
    """ Get key/value format dict from line
    Args:
        line (str): 1 line in the log
    Returns:
        key/value format dict
    """
    # get the index because it starts from the date= part
    start = line.find("date=")
    if start < 0:
        return None
    # start here
    d = {}
    status = "k"  # k is key, v is value
    q = False  # True if value is quoted
    buff = ""  # variable for buffer
    for c in line[start:]:
        if status == "k":
            if c == "=":
                key = buff
                buff = ""
                status = "v"
            elif c == const.DELIMITER:
                continue
            else:
                buff += c
        elif status == "v":
            if q == False and c == "\"":
                q = True
            elif (q == True and c == "\"") or (q == False and c in [const.DELIMITER, "\n"]):
                q = False
                value = buff
                buff = ""
                d[key] = value
                status = "k"
            else:
                buff += c
    if status == "v" and buff:
        d[key] = value
    return d


def exec(file: bytes, misp: ExpandedPyMISP) -> int:
    """ Register log files with MISP
    Args:
        file (bytes): log file path
        misp (ExpandedPyMISP): ExpandedPyMISP with registration available
    Returns:
        int: Number of registered events
    """
    count = 0
    with open(file) as f:
        ks = []
        for line in f:
            # ignore blank lines
            if not line:
                continue
            d = line_to_dict(line)
            if d is None:
                continue
            event = get_event(d)
            if event is None:
                continue
            # register
            register_misp(misp, event)
            count += 1
    return count


if __name__ == "__main__":
    # const.py setting value check
    # Suspend the process if the constants required for the script operation are not set
    check_result = []
    check_result.append(check_const(const.MISP_URL, "MISP_URL"))
    check_result.append(check_const(const.MISP_AUTHKEY, "MISP_AUTHKEY"))
    check_result.append(check_const(const.LAST_FILE_NAME, "EVENT_DATE_DAT"))
    check_result.append(check_const(
        const.RETRY_MAXIMUM_LIMIT, "RETRY_MAXIMUM_LIMIT"))
    check_result.append(check_const(
        const.COMMAND_INTERVAL_TIME, "COMMAND_INTERVAL_TIME"))
    check_result.append(check_const(
        const.DUPLICATE_EVENT_CONFIRM_WORD, "DUPLICATE_EVENT_CONFIRM_WORD"))
    # Exit if there is even one error
    if False in check_result:
        print("operation of the Script have not been set.")
        sys.exit(1)

    print("Script execution started")
    start_time = datetime.datetime.now().strftime("%Y/%m/%d %X")
    print(start_time)

    # Email subject of Script processing result
    # Embed the date and time if there is {} in the setting value
    now_time = datetime.datetime.now().strftime("%Y/%m/%d %X")
    mail_subject = f"{const.MAIL_SUBJECT}: {now_time}"

    # Variable to add Script processing result to mail body
    mail_buffer = []
    mail_buffer.append(f"Script start time: {start_time}")

    # Variable to add error output to email body
    error_files = []

    # Check the existence of the file that recorded the date of the last registered event
    if const.LAST_FILE_NAME.is_file() == False:
        const.LAST_FILE_NAME.touch()

    # Get the dates of registered events
    with const.LAST_FILE_NAME.open(mode="r") as f:
        last_file_name = f.read()

    # get file names after last_file_name
    dir = get_dir()
    files = os.listdir(dir)
    files = [f for f in files if os.path.isfile(os.path.join(dir, f))]
    files = sorted(files)

    # variables for counting
    normal_count = 0
    error_count = 0
    file_count = 0
    event_count = 0

    # MISP connection
    misp = ExpandedPyMISP(
        const.MISP_URL,
        const.MISP_AUTHKEY,
        ssl=False,
        debug=False)

    # rope from date_for
    for file in files:
        # Don't process anything before last_file_name
        if last_file_name and file <= last_file_name:
            continue

        # process the file
        try:
            event_count += exec(os.path.join(dir, file), misp)
            normal_count += 1
        except Exception:
            except_return = traceback.format_exc()
            print(except_return)
            error_count += 1

        file_count += 1

    # ending time
    end_time = datetime.datetime.now().strftime("%Y/%m/%d %X")

    # save the date of the next execution to a file
    with const.LAST_FILE_NAME.open("w") as f:
        f.write(file)

    mail_buffer.append(f"Registered event:{event_count}")

    mail_buffer.append("number of successful files / total number of files")
    success_event = f"{normal_count} / {file_count}"
    mail_buffer.append(success_event)

    mail_buffer.append("number of failed files / total number of files")
    failure_event = f"{error_count} / {file_count}"
    mail_buffer.append(failure_event)

    mail_buffer.append(f"Script end time: {end_time}")

    mail_send(mail_buffer)

    print("Completed all steps")

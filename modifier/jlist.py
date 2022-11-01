import abc
from modifier.abstract import AbstractModifier

class JListModifier(AbstractModifier):
    """ JList class for modifier """

    def modify_label(self, message_Id, d):
        """ modify to JLIST label
        Args:
            message_id (str): Message ID
            d (dict): key/value format dict

        Returns:
            str: Label when changing, None if not hit
        """
        
        if message_Id == "008212":
            return "JLIST_AV"
        if message_Id == "054803":
            if d.get("catdesc") in ["DCJUST_Domain_Block_Filter", "DCJUST_Domain_Detect_Filter"]:
                return "JLIST_Domain"
        if message_Id == "013056":
            if d.get("catdesc") in ["DCJUST_URL_Block_Filter", "DCJUST_URL_Detect_Filter"]:
                return "JLIST_URL"
        if message_Id == "000013":
            if d.get("policyname") in ["DCJUST_IP_Block_1", "DCJUST_IP_Detect_1"]:
                return "JLIST_IP"        
        return None

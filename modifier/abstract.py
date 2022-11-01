import abc

class AbstractModifier(object, metaclass=abc.ABCMeta):
    """ abstract class for modifier """

    @abc.abstractmethod
    def modify_label(self, message_id: str, d: dict) -> str:        
        """ modify the label
        Args:
            message_id (str): Message ID
            d (dict): key/value format dict

        Returns:
            str: Label when changing, None if not hit
        """
        pass

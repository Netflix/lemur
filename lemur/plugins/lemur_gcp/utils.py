def get_name_from_self_link(self_link):
    """
    Returns the resource name from a self_link name.
    :param self_link:
    :return:
    """
    return self_link.split("/")[-1]

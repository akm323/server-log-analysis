def set_path():
    import os
    # Get the current directory
    current_dir = os.path.dirname(os.path.realpath(__file__))
    # Navigate one directory back
    parent_dir = os.path.dirname(current_dir)
    return parent_dir

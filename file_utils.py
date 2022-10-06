import os


def read_file(filepath):
    if not os.path.exists(filepath):
        return None

    with open(filepath, "rb") as file:
        file_content = file.read()

    return file_content


def write_file(filepath, content):
    # write/replace the contents of the file if exists.
    # If the file does not exist, then this function creates one and then writes data to it
    with open(filepath, "wb") as file:
        file.write(content)

    return filepath


def delete_file(filepath):

    if not os.path.exists(filepath):
        return

    os.remove(path=filepath)


class fileUtil:
    pass

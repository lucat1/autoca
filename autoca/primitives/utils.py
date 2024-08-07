from pathlib import Path
# Check if the file exists or the content is equal to content. If is not equal 
# write the content to the file
def check_write_file(file_path: Path, content: bytes):
    try:
        crt = open(file_path, "rb")
        if crt.read() == content:
            return
        crt.close()

        crt = open(file_path, "wb")
        crt.write(content)
        crt.close()
    except FileNotFoundError:
        crt = open(file_path, "wb")
        crt.write(content)
        crt.close()
        return

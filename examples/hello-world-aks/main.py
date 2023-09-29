import subprocess
import string
import os
import stat


def index():
    filename = "./verbose-report"
    # make sure the file is executable
    if not os.access(filename, os.X_OK):
        # make it executable if it's not
        st = os.stat(filename)
        os.chmod(filename, st.st_mode |
                 stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    out = (subprocess.run(filename,
                          capture_output=True, encoding="UTF-8")).stdout

    formatted_text = out.replace("\n", " ").split(" ")
    formatted_text = [x for x in formatted_text if x != ""]

    def is_hex(x): return all(c in string.hexdigits for c in x)

    out = []
    temp_out = ["<br>"]
    counter = 0
    for item in formatted_text:
        if item.endswith(":"):
            temp_out.append(item)
            temp_out.append("<br>")
            # bold the header
            out.append("<strong>")
            out.append(" ".join(temp_out))
            out.append("</strong>")
            temp_out = ["<br>"]
            counter = 0

        # these are the header words before the colon at the end of the line
        elif not is_hex(item):
            temp_out.append(item)
            counter = 0
        # fall-through case of data
        else:
            if counter == 2:
                out.append("<br>")
                counter = 0
            out.append(item)
            counter += 1

    # ACI image source
    image = "<img src=\"https://azure.microsoft.com/svghandler/kubernetes-service?width=600&height=315\" alt=\"Microsoft ACI Logo\" width=\"600\" height=\"315\"><br>"
    style = """
    <style>
        body {
            text-align: center;
            font-family: 'Courier New', monospace;
        }
    </style>
    """
    # put everything together
    return (
        style +
        "<div>" + "<h1>Welcome to Confidential Pods on Azure Kubernetes Service!</h1>" +
        image + " ".join(out) +
        "</div>"
    )


# main driver function
if __name__ == '__main__':
    html = index()

    filename = "/usr/share/nginx/html/index.html"
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w") as f:
        f.write(html)

    out = (subprocess.run(["/usr/sbin/nginx", "-g", "daemon off;"],
                          capture_output=True, encoding="UTF-8")).stdout
    
    print(out)

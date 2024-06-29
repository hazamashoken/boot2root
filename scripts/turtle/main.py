import re

ROTATE = re.compile(r"Tourne (gauche|droite) de (\d+) degrees")
FORWARD = re.compile(r"Avance (\d+) spaces")
BACKWARD = re.compile(r"Recule (\d+) spaces")

with open("turtle.md") as fd:
    for line in fd:
        if not line.strip():
            print("wait 120")
            print("clean")

        search = ROTATE.search(line)
        if search:
            direction, angle = search.groups()
            if direction == "gauche":
                print(f"lt {angle}")
            else:
                print(f"rt {angle}")
            continue

        search = FORWARD.search(line)
        if search:
            print(f"fd {search.group(1)}")
            continue

        search = BACKWARD.search(line)
        if search:
            print(f"bk {search.group(1)}")
            continue
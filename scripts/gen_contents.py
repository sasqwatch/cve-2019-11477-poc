import sys

def usage():
    print ("Generate contents with the given name and size")
    print ("Usage: python3 gen_contents.py <name> <size>")
    exit(1)

def generate(ofname, sz):
    of = open(ofname, "w")
    for i in range(sz):
        of.write('A')
    of.close()

def main():
    if len(sys.argv) != 3:
        usage()

    ofname = sys.argv[1]
    sz = int(sys.argv[2])

    generate(ofname, sz)

if __name__ == "__main__":
    main()

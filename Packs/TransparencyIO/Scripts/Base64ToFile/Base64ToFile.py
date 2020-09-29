import base64

def main():
    outfilename = demisto.args()['Filename']
    bin_file = base64.decodestring(demisto.args()['Input'].encode('utf-8'))
    result = fileResult(filename=outfilename, data=bin_file)
    result['Type'] = entryTypes['image']
    demisto.results(result)

if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
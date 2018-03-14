""" Extract inline docs from a header file into an rst file for sphinx """
import sys

SCANNING, DOCS, FUNC = 1, 2, 3

def get_doc_lines(l):
    if l.startswith('.. '):
        return ['   ' + l, '']
    return ['   ' + l]

def output_func(docs, func):
    is_normal_ret = 'WALLY_CORE_API int' in func
    func = func[:-1].replace('WALLY_CORE_API','').strip()
    func = func.replace(',',', ').replace('  ', ' ')
    ret = ['.. c:function:: ' + func, '']
    seen_param = False
    for l in docs:
        ret.extend(get_doc_lines(l))
    if is_normal_ret:
        ret.append('   :return: WALLY_OK or an error code.') # FIXME: Link
        ret.append('   :rtype: int')
    ret.append('')
    ret.append('')
    return ret


def extract_docs(filename):

    lines = [l.strip() for l in open(filename).readlines()]
    title = filename.split('_')[1][:-2].capitalize() + ' Functions'
    title_markup = '=' * len(title)
    output, current, func, state = [title, title_markup, ''], [], '', SCANNING

    for l in lines:
        if state == SCANNING:
            if l.startswith('/**') and '*/' not in l:
                current, func, state = [l[3:]], '', DOCS
        elif state == DOCS:
            if l == '*/':
                state = FUNC
            else:
                assert l.startswith('*'), l
                if l.startswith('*|'):
                    current[-1] += ' ' + l[2:].strip()
                else:
                    current.append(l[1:].strip())
        else: # FUNC
            func += l
            if ');' in func:
                output.extend(output_func(current, func))
                state = SCANNING

    print '\n'.join(output)


if __name__ == '__main__':
    extract_docs(sys.argv[1])

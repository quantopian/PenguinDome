def get_bool(prompt, default=None):
    if default is not None:
        default = 'y' if default else 'n'
    full_prompt = prompt
    if default:
        full_prompt += ' [{}]'.format(default)
    full_prompt += ' '
    answer = input(full_prompt)
    if answer == '':
        answer = default
    if not answer:
        return get_bool(prompt, default)
    if answer.lower()[0] in ('y', 't', '1'):
        return True
    if answer.lower()[0] in ('n', 'f', '0'):
        return False
    return get_bool(prompt, default)


def get_int(prompt, default=None, minimum=None):
    full_prompt = prompt
    if default is not None:
        full_prompt += ' [{}]'.format(default)
    full_prompt += ' '
    answer = input(full_prompt)
    if answer == '':
        answer = default
    if answer is None:
        return get_int(prompt, default, minimum)
    try:
        answer = int(answer)
        if minimum is not None and answer < minimum:
            print('The minimum is {}'.format(minimum))
            return get_int(prompt, default, minimum)
        return answer
    except:
        return get_int(prompt, default, minimum)


def get_string(prompt, default=None, none_ok=False):
    full_prompt = prompt
    if default:
        full_prompt += ' [{}]'.format(default)
        if none_ok:
            full_prompt += ' [enter "none" to clear]'
    full_prompt += ' '
    answer = input(full_prompt)
    if answer == '':
        answer = default
    if answer == 'none':
        answer = ''
    if answer is None:
        return get_string(prompt, default)
    return answer


def get_string_or_list(prompt, default=None):
    so_far = []
    while True:
        full_prompt = prompt
        if default and not so_far:
            if isinstance(default, str):
                full_prompt += ' [{}]'.format(default)
            else:
                full_prompt += ' [{}]'.format(', '.join(default))
        if so_far:
            full_prompt += ' [hit Enter when finished]'
        full_prompt += ' '
        answer = input(full_prompt)
        if not answer:
            if so_far:
                # Canonicalize for comparison purposes.
                so_far.sort()
                return so_far
            answer = default
        if answer is None:
            return get_string_or_list(prompt, default)
        if isinstance(answer, str):
            so_far.append(answer)
        else:
            so_far.extend(answer)

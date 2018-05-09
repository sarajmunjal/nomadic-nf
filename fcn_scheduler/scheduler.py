import subprocess

CONTEXT = 0

def get_active_list():
    functions_list = subprocess.check_output(["gcloud", "beta", "functions", "list"])
    functions_list = functions_list.split("\n")[1:]
    active_list = []
    for function in functions_list:
        params = function.split()
        if len(params) != 5:   #Hack To avoid weird shit
            continue
        if params[1] == 'ACTIVE':
            active_list.append(params[0])
            return active_list



def get_function_description(functions):
    trigger_url_dict = {}
    for function in functions:
        description = subprocess.check_output(["gcloud", "beta", "functions", "describe", function])
        d_list = description.split('\n')
        trigger_url = ""
        for item in d_list:
            if item == 'httpsTrigger:':
                trigger_url = d_list[d_list.index(item)+1]
                trigger_url = trigger_url.strip()
                trigger_url = trigger_url.split(':', 1)
                trigger_url = trigger_url[1]
                trigger_url = trigger_url.strip()
                trigger_url_dict[function] = trigger_url
    return trigger_url_dict


def schedule_service(context, service_list, mode='default'):
    if mode == 'default':
        mode = 'round-robin' #Current default mode is round-robin

        if mode == 'random':
            return context, random.choice(service_list)
        if mode == 'round-robin':
            next_index = (context + 1)%len(service_list)
            return next_index, service_list[next_index]

if __name__ == "__main__":
    active_functions = get_active_list()
    trigger_table = get_function_description(active_functions)
    CONTEXT, chosen_function = schedule_service(CONTEXT, active_functions)
    trigger_url = trigger_table[chosen_function]
    print("Chosen Function: {}\tURL: {}".format(chosen_function, trigger_url))


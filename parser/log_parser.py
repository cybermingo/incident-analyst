def parse_log_line(line):
    parts = line.strip().split()

    if len(parts) < 3:
        return None

    timestamp = parts[0] + " " + parts[1]
    event = parts[2]

    data = {
        "timestamp": timestamp,
        "event": event
    }

    for item in parts[3:]:
        if "=" in item:
            key, value = item.split("=", 1)
            data[key] = value

    return data


def parse_log_file(file_path):
    events = []

    with open(file_path, "r") as file:
        for line in file:
            parsed = parse_log_line(line)
            if parsed:
                events.append(parsed)

    return events
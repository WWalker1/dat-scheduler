import os

def aggregate_files(file_list, output_file='snapshot.txt'):
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for filename in file_list:
            if os.path.exists(filename):
                outfile.write(f"# File: {filename}\n\n")
                with open(filename, 'r', encoding='utf-8') as infile:
                    outfile.write(infile.read())
                outfile.write("\n\n")
            else:
                print(f"Warning: File {filename} not found.")
    
    print(f"Aggregated code saved to {output_file}")


def get_filenames(subdir):  # Define a function that takes a subdirectory name as input
    return [os.path.join(subdir, file) for file in os.listdir(subdir)]  # Return a list of filenames preceded by the subdirectory name using a list comprehension


# Example usage

files_to_aggregate = ['app.py']
files_to_aggregate += get_filenames("templates")

print(files_to_aggregate)

aggregate_files(files_to_aggregate)
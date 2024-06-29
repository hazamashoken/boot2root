import itertools
import subprocess

# Set of remaining values
remaining_values = [1, 2, 3, 5, 6]

# Generate all permutations of the remaining values
permutations = list(itertools.permutations(remaining_values))

# Add 4 as the first element to each permutation
solutions = [[4] + list(p) for p in permutations]

# Function to call the bomb binary with a given solution
def call_bomb(solution, i):
    solution_str = ' '.join(map(str, solution))
    ret = """Public speaking is very easy.
1 2 6 24 120 720
1 b 214
9
opukmq
{} 
""".format(solution_str)
    try:
        with open("./tmp/tmp{}.txt".format(i), "w") as f:
            f.write(ret)
            f.close()
        result = subprocess.run(['./bomb', "./tmp/tmp{}.txt".format(i)], input=solution_str, text=True, capture_output=True)
        with open("./ret/ret{}.txt".format(i), "w") as f:
            f.write(result.stdout)
            f.close()
    except subprocess.CalledProcessError as e:
        print(f"Failed to run bomb with solution {solution_str}: {e}")

# Call the bomb binary for each solution
for i, solution in enumerate(solutions):
    call_bomb(solution, i)
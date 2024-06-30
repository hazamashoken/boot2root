import itertools
import subprocess

remaining_values = [1, 2, 3, 5, 6]

permutations = list(itertools.permutations(remaining_values))

solutions = [[4] + list(p) for p in permutations]

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

for i, solution in enumerate(solutions):
    call_bomb(solution, i)
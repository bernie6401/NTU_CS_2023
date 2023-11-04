import angr
import claripy

# 建立一個project
root = 'Reverse/Lab3/Super Angry/'
proj = angr.Project(root + 'super_angry')

# 建立Claripy Symbol
sym_arg = claripy.BVS('sym_arg', 8 * 32) # 就像z3一樣要建立symbol

# 建立初始的state
state = proj.factory.entry_state(args=[proj.filename, sym_arg])
simgr = proj.factory.simulation_manager(state)

# 有了proj/symbol/initial state之後就要開始讓他跑起來
simgr.explore(find = lambda s: b'Correct!' in  s.posix.dumps(1))

if len(simgr.found) > 0:
    print(simgr.found[0].solver.eval(sym_arg, cast_to=bytes))
else:
    print("NONONONO")
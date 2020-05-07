import gdb
import walkers
import taintchecker as tc


class SS(walkers.Walker):
	"""A simple demo that traverse:
	typedef struct s {
		int* i;
		int j;
	}s;
	Use:
		gdb-pipe simple-struct <struct_pointer_variable>"""

	name = 'simple-struct'
	tags = ['demo']

	def __init__(self, start_expr):
		self.start_expr = start_expr
		# explain is yielded as output
		self.explain = ""

	@classmethod
	def from_userstring(cls, args, first, last):
		return cls(args)

	def iter_struct(self, init_addr):
		# i
		i_p = init_addr.dereference()['i']
		# *i
		i = i_p.dereference()
		# j
		j = init_addr.dereference()['j']
		# Get the memory address of *i and j
		i_addr = i.address
		j_addr = j.address
		# Check their taints
		i_taint = gdb.execute("monitor lookup {}".format(i_addr), to_string=True)
		self.explain += tc.check("*i", i, i_taint)
		j_taint = gdb.execute("monitor lookup {}".format(j_addr), to_string=True)
		self.explain += tc.check("j", j, j_taint)
		yield self.explain

	def iter_def(self, inpipe):
		yield from self.call_with(inpipe, self.iter_struct, self.start_expr)

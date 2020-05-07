import gdb


def num_taint(taint):
	"""Return the number of a memory address' taint
	A taint looks like this:
		[ 0x080766a4 ]-> {9,19}
	This function then should return 2

	We may receive an ill-formatted taint, in which case we return 0.
	"""
	# An ill-formatted taint 
	if taint[0] != "[":
		return 0
	else:
		t = taint.strip().split()
		address = t[1]			# 0x080766a4
		taints = t[3][1:-1]		# 9,19
		return len(taints.strip().split(","))


def check(name, value, taint):
	"""Check if a value violates the number of taints 
	it is allowed to have. For a primitive value, at
	most one taint is allowed. For other types, we 
	enforce no limitations so far.
	
	An explain string is returned if violation is
	detected. If no violation, an empty string 
	is returned."""
	explain = ""
	value_type = value.type
	# primitive types
	if value_type.code == gdb.TYPE_CODE_INT or \
	   value_type.code == gdb.TYPE_CODE_FLT or \
	   value_type.code == gdb.TYPE_CODE_CHAR or \
	   value_type.code == gdb.TYPE_CODE_BOOL or \
	   value_type.code == gdb.TYPE_CODE_DECFLOAT:
		taint_size = num_taint(taint)
		if taint_size > 1:
			explain += "{}: a heap value of a primitive type {}, but it contains {} taints".format(name, value_type.name, taint_size)
	return explain
	

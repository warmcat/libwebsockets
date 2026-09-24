#!/usr/bin/env python3
#
# Summarize gcov-format coverage of a build tree after ctest has run in it.
#
# The tree must have been configured with -DLWS_WITH_GCOV=1 (gcc or clang):
# every test process then leaves .gcda counters next to its objects when it
# exits.  This script runs gcov (or llvm-cov gcov for clang-built trees) over
# every .gcno in the build tree, merges the results per source file, and
# prints
#
#  - overall line and function coverage of the library sources,
#  - a per-directory table, worst first,
#  - every function that was built but has no or thin line coverage, worst
#    first.
#
# It only reports; it never fails the build.  Missing tools or unreadable
# data files are printed as warnings and the exit code is still 0.
#
#   coverage-report.py [--build-dir B] [--source-dir S] [--compiler CC]
#                      [--gcov "TOOL [ARGS]"] [--include PREFIX]...
#                      [--threshold PCT] [--limit N] [--json-out FILE]
#
# `make coverage` in a gcov-instrumented tree runs it with the right paths.

import argparse, collections, concurrent.futures, glob, gzip, json, os, re
import shutil, subprocess, sys, tempfile


def find_tool(explicit, compiler):
	"""Pick the gcov reader that matches the compiler that made the .gcno."""
	if explicit:
		return explicit.split()

	cands = []
	base = os.path.basename(compiler or "")
	if "clang" in base:
		# clang's gcov files need llvm-cov; gcc's gcov rejects them
		p = subprocess.run([compiler, "-print-prog-name=llvm-cov"],
				   capture_output=True, text=True).stdout.strip()
		if p and os.sep in p:
			cands.append([p, "gcov"])
		cands.append(["llvm-cov", "gcov"])
		cands += [["llvm-cov-%d" % v, "gcov"] for v in range(40, 9, -1)]
		for c in cands:
			if shutil.which(c[0]):
				return c
		# gcc's gcov rejects (and can crash on) clang's files: give up
		return None
	elif compiler:
		p = subprocess.run([compiler, "-print-prog-name=gcov"],
				   capture_output=True, text=True).stdout.strip()
		if p and os.sep in p:
			cands.append([p])
	cands.append(["gcov"])

	for c in cands:
		if shutil.which(c[0]):
			return c

	return None


def tool_mode(tool):
	"""'json' for gcc gcov >= 9 (--json-format), else 'text' (-i)."""
	if "llvm-cov" in os.path.basename(tool[0]):
		return "text"
	v = subprocess.run(tool + ["--version"], capture_output=True,
			   text=True).stdout
	m = re.search(r"\) (\d+)\.", v)
	if m and int(m.group(1)) >= 9:
		return "json"

	return "text"


class Cov:
	def __init__(self):
		# file -> { "lines": {line: count}, "funcs": {(name, start): [count, end]} }
		self.files = collections.defaultdict(
			lambda: {"lines": collections.Counter(), "funcs": {}})
		self.errors = []

	def add_func(self, f, name, start, end, count):
		d = self.files[f]["funcs"]
		k = (name, start)
		if k in d:
			d[k][0] += count
			d[k][1] = max(d[k][1], end)
		else:
			d[k] = [count, end]

	def add_line(self, f, line, count):
		self.files[f]["lines"][line] += count


def parse_json(path, cov, norm):
	with gzip.open(path, "rt") as fp:
		d = json.load(fp)
	for fl in d.get("files", []):
		f = norm(fl["file"])
		if not f:
			continue
		for fn in fl.get("functions", []):
			cov.add_func(f, fn["name"], fn["start_line"],
				     fn.get("end_line", fn["start_line"]),
				     fn.get("execution_count", 0))
		for ln in fl.get("lines", []):
			cov.add_line(f, ln["line_number"], ln.get("count", 0))


def parse_text(path, cov, norm):
	"""gcov 7/8 and llvm-cov gcov -i intermediate text format."""
	f = None
	with open(path, errors="replace") as fp:
		for line in fp:
			line = line.rstrip("\n")
			if line.startswith("file:"):
				f = norm(line[5:])
				continue
			if not f:
				continue
			if line.startswith("function:"):
				a = line[9:].split(",")
				if len(a) >= 4:		# start,end,count,name
					start, end, count = int(a[0]), int(a[1]), int(a[2])
					name = ",".join(a[3:])
				elif len(a) == 3:	# gcc 7: start,count,name
					start, count, name = int(a[0]), int(a[1]), a[2]
					end = start
				else:
					continue
				cov.add_func(f, name, start, end, count)
			elif line.startswith("lcount:"):
				a = line[7:].split(",")
				if len(a) >= 2:
					cov.add_line(f, int(a[0]), int(a[1]))


def run_one(tool, mode, gcno, tmp):
	"""Run the reader on one .gcno in its own scratch dir, return outputs."""
	d = tempfile.mkdtemp(dir=tmp)
	flags = ["--json-format"] if mode == "json" else ["-i"]
	r = subprocess.run(tool + flags + ["-o", os.path.dirname(gcno), gcno],
			   cwd=d, capture_output=True, text=True)
	outs = glob.glob(os.path.join(d, "*.gcov.json.gz")) if mode == "json" \
		else glob.glob(os.path.join(d, "*.gcov"))
	err = None
	if r.returncode or not outs:
		err = "%s: rc %d: %s" % (gcno, r.returncode,
					 (r.stderr or r.stdout).strip()[:200])
	return outs, err


def pct(n, d):
	return 100.0 * n / d if d else 0.0


def main():
	ap = argparse.ArgumentParser()
	ap.add_argument("--build-dir", default=os.getcwd())
	ap.add_argument("--source-dir", default=None)
	ap.add_argument("--compiler", default=None,
			help="C compiler the tree was built with (picks the reader)")
	ap.add_argument("--gcov", default=None,
			help="reader to use, eg 'gcov-14' or 'llvm-cov gcov'")
	ap.add_argument("--include", action="append", default=None,
			help="source prefix to count (default: lib)")
	ap.add_argument("--threshold", type=float, default=50.0,
			help="list functions below this line coverage %% (default 50)")
	ap.add_argument("--limit", type=int, default=0,
			help="max functions to list, 0 = all")
	ap.add_argument("--json-out", default=None,
			help="also write a machine-readable summary here")
	a = ap.parse_args()

	bdir = os.path.abspath(a.build_dir)
	sdir = os.path.abspath(a.source_dir) if a.source_dir else \
		os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
	incl = a.include or ["lib"]
	incl = [p.rstrip("/") + "/" for p in incl]

	compiler = a.compiler
	if not compiler:
		try:
			with open(os.path.join(bdir, "CMakeCache.txt")) as fp:
				for line in fp:
					if line.startswith("CMAKE_C_COMPILER:"):
						compiler = line.split("=", 1)[1].strip()
		except OSError:
			pass

	tool = find_tool(a.gcov, compiler)
	if not tool:
		print("coverage: no gcov reader found for compiler %s (a clang "
		      "build needs llvm-cov, gcc's gcov cannot read its files); "
		      "nothing to report" % compiler)
		return 0
	mode = tool_mode(tool)

	gcnos = []
	for root, dirs, files in os.walk(bdir):
		gcnos += [os.path.join(root, f) for f in files if f.endswith(".gcno")]
	if not gcnos:
		print("coverage: no .gcno files under %s; was the tree built with "
		      "-DLWS_WITH_GCOV=1 ?" % bdir)
		return 0

	gcdas = sum(1 for g in gcnos if os.path.exists(g[:-5] + ".gcda"))
	print("coverage: %d objects instrumented, %d with run data, reader %s (%s)" %
	      (len(gcnos), gcdas, " ".join(tool), mode))

	def norm(path):
		p = os.path.normpath(path)
		if not os.path.isabs(p):
			p = os.path.normpath(os.path.join(bdir, p))
		if p.startswith(sdir + os.sep):
			rel = p[len(sdir) + 1:]
		else:
			return None
		for i in incl:
			if rel.startswith(i):
				return rel
		return None

	cov = Cov()
	tmp = tempfile.mkdtemp(prefix="lws-cov-")
	try:
		with concurrent.futures.ThreadPoolExecutor(
				max_workers=os.cpu_count() or 2) as ex:
			for outs, err in ex.map(
					lambda g: run_one(tool, mode, g, tmp), gcnos):
				if err:
					cov.errors.append(err)
				for o in outs:
					try:
						if mode == "json":
							parse_json(o, cov, norm)
						else:
							parse_text(o, cov, norm)
					except (OSError, ValueError, KeyError) as e:
						cov.errors.append("%s: %s" % (o, e))
	finally:
		shutil.rmtree(tmp, ignore_errors=True)

	if not cov.files:
		print("coverage: no source under %s matched %s" % (sdir, incl))
		for e in cov.errors[:20]:
			print("  ", e)
		return 0

	# per-function line coverage from the lines inside its [start, end]

	funcs = []		# (pct, executed, total, file, start, name, count)
	dirs = collections.defaultdict(lambda: [0, 0, 0, 0])	# lines x/n, funcs x/n
	tl = te = tf = tfe = 0
	for f, d in sorted(cov.files.items()):
		lines = d["lines"]
		nl = len(lines)
		ne = sum(1 for c in lines.values() if c)
		nf = len(d["funcs"])
		nfe = sum(1 for c, _ in d["funcs"].values() if c)
		tl += nl; te += ne; tf += nf; tfe += nfe
		dd = dirs[os.path.dirname(f)]
		dd[0] += ne; dd[1] += nl; dd[2] += nfe; dd[3] += nf
		for (name, start), (count, end) in d["funcs"].items():
			fl = [c for l, c in lines.items() if start <= l <= end]
			n = len(fl)
			e = sum(1 for c in fl if c)
			funcs.append((pct(e, n), e, n, f, start, name, count))

	print()
	print("coverage: %s  lines %d / %d (%.1f%%)  functions %d / %d (%.1f%%)" %
	      (" ".join(i.rstrip("/") for i in incl), te, tl, pct(te, tl),
	       tfe, tf, pct(tfe, tf)))
	print()
	print("per directory, worst first:")
	for dname, (ne, nl, nfe, nf) in sorted(dirs.items(),
					       key=lambda kv: (pct(kv[1][0], kv[1][1]), kv[0])):
		print("  %5.1f%%  %6d / %6d lines  %4d / %4d functions  %s" %
		      (pct(ne, nl), ne, nl, nfe, nf, dname))

	thin = [x for x in funcs if x[0] < a.threshold]
	thin.sort(key=lambda x: (x[0], -x[2], x[3], x[4]))
	never = sum(1 for x in funcs if not x[6])
	print()
	print("functions below %.0f%% line coverage, worst first: %d of %d "
	      "(%d never executed)" % (a.threshold, len(thin), len(funcs), never))
	shown = thin[:a.limit] if a.limit else thin
	for p, e, n, f, start, name, count in shown:
		print("  %5.1f%%  %4d / %4d  %s:%d %s" % (p, e, n, f, start, name))
	if len(shown) < len(thin):
		print("  ... %d more" % (len(thin) - len(shown)))

	if cov.errors:
		print()
		print("coverage: %d objects could not be read (first few):" %
		      len(cov.errors))
		for e in cov.errors[:10]:
			print("  ", e)

	if a.json_out:
		with open(a.json_out, "w") as fp:
			json.dump({
				"lines": [te, tl], "functions": [tfe, tf],
				"directories": {k: v for k, v in dirs.items()},
				"thin": [{"pct": p, "lines": [e, n], "file": f,
					  "line": s, "name": nm, "count": c}
					 for p, e, n, f, s, nm, c in thin],
			}, fp, indent=1)

	return 0


if __name__ == "__main__":
	sys.exit(main())

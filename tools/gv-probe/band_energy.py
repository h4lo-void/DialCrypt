import sys, wave, struct, cmath, math
def load(p, t0, dur):
    w = wave.open(p); sr = w.getframerate(); w.setpos(int(t0*sr)); n = int(dur*sr)
    d = struct.unpack("<%dh" % n, w.readframes(n)); return sr, d
def fft(x):
    n = len(x)
    if n == 1: return x
    e = fft(x[0::2]); o = fft(x[1::2])
    t = [cmath.exp(-2j*math.pi*k/n)*o[k] for k in range(n//2)]
    return [e[k]+t[k] for k in range(n//2)] + [e[k]-t[k] for k in range(n//2)]
def bands(p, t0, dur):
    sr, d = load(p, t0, dur); N = 1024; acc = [0.0]*(N//2)
    win = [0.5-0.5*math.cos(2*math.pi*i/N) for i in range(N)]
    for s in range(0, len(d)-N, N*2):
        X = fft([d[s+i]*win[i] for i in range(N)])
        for k in range(N//2): acc[k] += abs(X[k])**2
    tot = sum(acc) or 1.0; out = []
    for lo in range(0, 8000, 500):
        a = sum(acc[k] for k in range(N//2) if lo <= k*sr/N < lo+500)
        out.append("%4.1f" % (10*math.log10(a/tot+1e-12)))
    return " ".join(out)
print("band dB (500 Hz steps, 0-8k)")
print("tx:", bands(sys.argv[1], float(sys.argv[2]), 30))
print("rx:", bands(sys.argv[3], float(sys.argv[4]), 30))


"""Evidential risk fusion (Dempster-Shafer). Every method gives mass on Compromised (C) or 'don't know',
so Dempster's rule reduces to Bel(C) = 1 - prod(1 - r_i * m_i)."""

def discount(m, r):
    return r * m

def combine(masses, reliability):
    prod = 1.0
    for k, m in masses.items():
        prod *= 1 - discount(m, reliability.get(k, 1.0))
    return 1 - prod

def state_of(bel, th, trip=False):
    if trip or bel >= th["compromised"]:
        return 3, "Compromised"
    if bel >= th["suspicious"]:
        return 2, "Suspicious"
    if bel >= th["watch"]:
        return 1, "Watch"
    return 0, "Normal"

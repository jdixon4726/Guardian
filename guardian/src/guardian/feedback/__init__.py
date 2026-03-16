"""
Operator Feedback Loop

Allows operators to provide feedback on Guardian decisions (confirmed_correct,
false_positive, false_negative, known_pattern). Feedback is stored and used
to adjust Bayesian priors, cascade confidence, and scoring weights.
"""

/**
 * Error type: wrong predicate name on a built-in QL type
 * Error type: wrong arity (calling a 2-arg predicate with 3 args)
 */
from int x, int y
where
  x = 42 and
  y = x.toStringg() and
  //      ^^^^^^^^^ ERROR: 'toStringg' should be 'toString'
  x.strictconcat(y, x, y) and
  //^^^^^^^^^^^ ERROR: strictconcat takes 2 args, not 3
  x > 10
select x, y, x + y

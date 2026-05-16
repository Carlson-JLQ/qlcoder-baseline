/**
 * Error type: wrong arity (overrides takes 2 args, calling with 3)
 * Error type: using predicate with result in where clause
 */
import java

from Method m, Method n
where
  m.overrides(n, m) and
  //           ^^^^ ERROR: overrides takes (Method, Method), not 3 args
  m.getDeclaringType() and
  //                 ^^ ERROR: getDeclaringType() returns a RefType,
  //                    cannot be used as a standalone condition
  n.hasName("test")
select m, n, "m overrides n and m's declaring type is $@", m.getDeclaringType(), "type"

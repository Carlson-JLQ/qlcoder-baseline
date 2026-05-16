/**
 * Error type: unbound variable in select
 * Error type: Variable type mismatch in from clause
 */
import java

from Method m, string name
//             ^^^^^^^^^^^^ ERROR: 'string' type is not valid in from clause
//                          should be 'string' → need proper type
where
  m.hasName(name) and
  //        ^^^^ ERROR: hasName expects string, not a variable of type 'string'
  m.isPublic()
select m, name, x
//             ^ ERROR: 'x' is not bound

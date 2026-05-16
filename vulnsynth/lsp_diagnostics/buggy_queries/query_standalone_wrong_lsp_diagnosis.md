# LSP Diagnostic Report for `query_standalone_wrong.ql`

**Status**: ❌ 7 Error(s)
**Warnings**: 0

---

## Error 1: Line 10, Character 17

**Category**: `unknown`
**Message**: could not parse type name

### Source Context
```ql
      9 |   //      ^^^^^^^^^ ERROR: 'toStringg' should be 'toString'
>>>  10 |   x.strictconcat(y, x, y) and
     11 |   //^^^^^^^^^^^ ERROR: strictconcat takes 2 args, not 3
```

### LSP Context
**Valid alternatives**: abs, acos, asin, atan, bitAnd, bitNot, bitOr, bitShiftLeft

### Candidate Fixes
- LSP suggests these valid alternatives: abs, acos, asin, atan, bitAnd
- Review the CodeQL standard library documentation for the correct API at this position.

### Suggested Fix
```ql
// Fix suggestion for: 9 |   //      ^^^^^^^^^ ERROR: 'toStringg' should be 'toString'
>>>  10 |   x.strictconcat(y, x, y) and
     11 |   //^^^^^^^^^^^ ERROR: strictconcat takes 2 args, not 3
// See candidate fixes above.
```

---

## Error 2: Line 10, Character 2

**Category**: `expected_term`
**Message**: expected a term but found an expression instead

### Source Context
```ql
      9 |   //      ^^^^^^^^^ ERROR: 'toStringg' should be 'toString'
>>>  10 |   x.strictconcat(y, x, y) and
     11 |   //^^^^^^^^^^^ ERROR: strictconcat takes 2 args, not 3
```

### LSP Context
**Type/Hover**: **x**
**Valid alternatives**: x, y, any, none, QlBuiltins

### Candidate Fixes
- LSP suggests these valid alternatives: x, y, any, none, QlBuiltins
- LSP hover context: **x**
- Review the CodeQL standard library documentation for the correct API at this position.

### Suggested Fix
```ql
// Fix suggestion for: 9 |   //      ^^^^^^^^^ ERROR: 'toStringg' should be 'toString'
>>>  10 |   x.strictconcat(y, x, y) and
     11 |   //^^^^^^^^^^^ ERROR: strictconcat takes 2 args, not 3
// See candidate fixes above.
```

---

## Error 3: Line 10, Character 4

**Category**: `unknown`
**Message**: extraneous input 'strictconcat' expecting one of: '(', Lowerid

### Source Context
```ql
      9 |   //      ^^^^^^^^^ ERROR: 'toStringg' should be 'toString'
>>>  10 |   x.strictconcat(y, x, y) and
     11 |   //^^^^^^^^^^^ ERROR: strictconcat takes 2 args, not 3
```

### LSP Context
**Valid alternatives**: abs, acos, asin, atan, bitAnd, bitNot, bitOr, bitShiftLeft

### Candidate Fixes
- LSP suggests these valid alternatives: abs, acos, asin, atan, bitAnd
- Review the CodeQL standard library documentation for the correct API at this position.

### Suggested Fix
```ql
// Fix suggestion for: 9 |   //      ^^^^^^^^^ ERROR: 'toStringg' should be 'toString'
>>>  10 |   x.strictconcat(y, x, y) and
     11 |   //^^^^^^^^^^^ ERROR: strictconcat takes 2 args, not 3
// See candidate fixes above.
```

---

## Error 4: Line 10, Character 18

**Category**: `unknown`
**Message**: unexpected input ',' expecting one of: '::'

### Source Context
```ql
      9 |   //      ^^^^^^^^^ ERROR: 'toStringg' should be 'toString'
>>>  10 |   x.strictconcat(y, x, y) and
     11 |   //^^^^^^^^^^^ ERROR: strictconcat takes 2 args, not 3
```

### LSP Context
No LSP context available

### Candidate Fixes
- Review the CodeQL standard library documentation for the correct API at this position.

### Suggested Fix
```ql
// Fix suggestion for: 9 |   //      ^^^^^^^^^ ERROR: 'toStringg' should be 'toString'
>>>  10 |   x.strictconcat(y, x, y) and
     11 |   //^^^^^^^^^^^ ERROR: strictconcat takes 2 args, not 3
// See candidate fixes above.
```

---

## Error 5: Line 10, Character 24

**Category**: `unknown`
**Message**: unexpected input ')' expecting one of: <EOF>, 'and', 'as', 'boolean', 'class', 'newtype', 'date', 'float', 'from', 'implies', 'import', 'in', 'instanceof', 'int', 'module', 'or', 'order', 'predicate', 'select', 'string', 'where', '<', '<=', '=', '>', '>=', '-', ',', '!=', '/', '.', '*', '%', '+', Lowerid, Upperid, Atlowerid, '/**'

### Source Context
```ql
      9 |   //      ^^^^^^^^^ ERROR: 'toStringg' should be 'toString'
>>>  10 |   x.strictconcat(y, x, y) and
     11 |   //^^^^^^^^^^^ ERROR: strictconcat takes 2 args, not 3
```

### LSP Context
**Type/Hover**: **y**

### Candidate Fixes
- LSP hover context: **y**
- Review the CodeQL standard library documentation for the correct API at this position.

### Suggested Fix
```ql
// Fix suggestion for: 9 |   //      ^^^^^^^^^ ERROR: 'toStringg' should be 'toString'
>>>  10 |   x.strictconcat(y, x, y) and
     11 |   //^^^^^^^^^^^ ERROR: strictconcat takes 2 args, not 3
// See candidate fixes above.
```

---

## Error 6: Line 8, Character 8

**Category**: `cannot_resolve`
**Message**: toStringg() cannot be resolved for type int

### Source Context
```ql
      7 |   x = 42 and
>>>   8 |   y = x.toStringg() and
      9 |   //      ^^^^^^^^^ ERROR: 'toStringg' should be 'toString'
```

### LSP Context
**Valid alternatives**: abs, acos, asin, atan, bitAnd, bitNot, bitOr, bitShiftLeft

### Candidate Fixes
- Replace with a valid member: abs, acos, asin, atan, bitAnd
- Did you mean `toString`? (closest match to `toStringg`)

### Suggested Fix
```ql
// BEFORE (line 8):
7 |   x = 42 and
>>>   8 |   y = x.toStringg() and
      9 |   //      ^^^^^^^^^ ERROR: 'toStringg' should be 'toString'

// AFTER (suggested fix):
7 |   x = 42 and
>>>   8 |   y = x.toString() and
      9 |   //      ^^^^^^^^^ ERROR: 'toString' should be 'toString'
```

---

## Error 7: Line 10, Character 17

**Category**: `cannot_resolve`
**Message**: could not resolve type 

### Source Context
```ql
      9 |   //      ^^^^^^^^^ ERROR: 'toStringg' should be 'toString'
>>>  10 |   x.strictconcat(y, x, y) and
     11 |   //^^^^^^^^^^^ ERROR: strictconcat takes 2 args, not 3
```

### LSP Context
**Valid alternatives**: abs, acos, asin, atan, bitAnd, bitNot, bitOr, bitShiftLeft

### Candidate Fixes
- Replace with a valid member: abs, acos, asin, atan, bitAnd

### Suggested Fix
```ql
// Fix suggestion for: 9 |   //      ^^^^^^^^^ ERROR: 'toStringg' should be 'toString'
>>>  10 |   x.strictconcat(y, x, y) and
     11 |   //^^^^^^^^^^^ ERROR: strictconcat takes 2 args, not 3
// See candidate fixes above.
```

---

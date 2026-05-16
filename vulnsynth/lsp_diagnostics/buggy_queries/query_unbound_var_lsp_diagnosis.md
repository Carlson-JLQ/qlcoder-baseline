# LSP Diagnostic Report for `query_unbound_var.ql`

**Status**: ❌ 3 Error(s)
**Warnings**: 0

---

## Error 1: Line 5, Character 7

**Category**: `cannot_resolve`
**Message**: could not resolve module java

### Source Context
```ql
      4 |  */
>>>   5 | import java
      6 | 
```

### LSP Context
**Valid alternatives**: QlBuiltins

### Candidate Fixes
- Replace with a valid member: QlBuiltins

### Suggested Fix
```ql
// Fix suggestion for: 4 |  */
>>>   5 | import java
      6 |
// See candidate fixes above.
```

---

## Error 2: Line 7, Character 5

**Category**: `cannot_resolve`
**Message**: could not resolve type Method

### Source Context
```ql
      6 | 
>>>   7 | from Method m, string name
      8 | //             ^^^^^^^^^^^^ ERROR: 'string' type is not valid in from clause
```

### LSP Context
**Valid alternatives**: boolean, date, float, int, string, QlBuiltins, where, select

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, string

### Suggested Fix
```ql
// Fix suggestion for: 6 | 
>>>   7 | from Method m, string name
      8 | //             ^^^^^^^^^^^^ ERROR: 'string' type is not valid in from clause
// See candidate fixes above.
```

---

## Error 3: Line 14, Character 16

**Category**: `cannot_resolve`
**Message**: could not resolve variable x

### Source Context
```ql
     13 |   m.isPublic()
>>>  14 | select m, name, x
     15 | //             ^ ERROR: 'x' is not bound
```

### LSP Context
**Valid alternatives**: m, name, any, none, QlBuiltins

### Candidate Fixes
- Replace with a valid member: m, name, any, none, QlBuiltins

### Suggested Fix
```ql
// Fix suggestion for: 13 |   m.isPublic()
>>>  14 | select m, name, x
     15 | //             ^ ERROR: 'x' is not bound
// See candidate fixes above.
```

---

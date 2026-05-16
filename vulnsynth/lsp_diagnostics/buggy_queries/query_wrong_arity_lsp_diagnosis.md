# LSP Diagnostic Report for `query_wrong_arity.ql`

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
>>>   7 | from Method m, Method n
      8 | where
```

### LSP Context
**Valid alternatives**: boolean, date, float, int, string, QlBuiltins, where, select

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, string

### Suggested Fix
```ql
// Fix suggestion for: 6 | 
>>>   7 | from Method m, Method n
      8 | where
// See candidate fixes above.
```

---

## Error 3: Line 7, Character 15

**Category**: `cannot_resolve`
**Message**: could not resolve type Method

### Source Context
```ql
      6 | 
>>>   7 | from Method m, Method n
      8 | where
```

### LSP Context
**Valid alternatives**: boolean, date, float, int, string, QlBuiltins

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, string

### Suggested Fix
```ql
// Fix suggestion for: 6 | 
>>>   7 | from Method m, Method n
      8 | where
// See candidate fixes above.
```

---

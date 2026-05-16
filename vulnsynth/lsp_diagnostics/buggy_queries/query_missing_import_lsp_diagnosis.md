# LSP Diagnostic Report for `query_missing_import.ql`

**Status**: ❌ 9 Error(s)
**Warnings**: 2

---

## Error 1: Line 5, Character 7

**Category**: `cannot_resolve`
**Message**: could not resolve module java

### Source Context
```ql
      4 |  */
>>>   5 | import java
      6 | import semmle.code.java.dataflow.DataFlow
```

### LSP Context
**Valid alternatives**: QlBuiltins

### Candidate Fixes
- Replace with a valid member: QlBuiltins

### Suggested Fix
```ql
// Fix suggestion for: 4 |  */
>>>   5 | import java
      6 | import semmle.code.java.dataflow.DataFlow
// See candidate fixes above.
```

---

## Error 2: Line 6, Character 7

**Category**: `cannot_resolve`
**Message**: could not resolve module semmle.code.java.dataflow.DataFlow

### Source Context
```ql
      5 | import java
>>>   6 | import semmle.code.java.dataflow.DataFlow
      7 | // MISSING: import semmle.code.java.dataflow.FlowSources
```

### LSP Context
**Type/Hover**: **query_missing_import**

 Error type: missing import (RemoteFlowSource used without import)
 Error type: wrong class name in extends (DataFlow::Config vs DataFlow::Configuration)
**Valid alternatives**: QlBuiltins

### Candidate Fixes
- Replace with a valid member: QlBuiltins
- The expected type is `missing`. Make sure the predicate you're calling exists on this type.

### Suggested Fix
```ql
// Fix suggestion for: 5 | import java
>>>   6 | import semmle.code.java.dataflow.DataFlow
      7 | // MISSING: import semmle.code.java.dataflow.FlowSources
// See candidate fixes above.
```

---

## Error 3: Line 9, Character 23

**Category**: `cannot_resolve`
**Message**: could not resolve module DataFlow

### Source Context
```ql
      8 | 
>>>   9 | class MyConfig extends DataFlow::Configuration {
     10 |   //                ^^^^^^^^^^^^^^^^^^^^^^
```

### LSP Context
**Valid alternatives**: MyConfig, QlBuiltins

### Candidate Fixes
- Replace with a valid member: MyConfig, QlBuiltins

### Suggested Fix
```ql
// Fix suggestion for: 8 | 
>>>   9 | class MyConfig extends DataFlow::Configuration {
     10 |   //                ^^^^^^^^^^^^^^^^^^^^^^
// See candidate fixes above.
```

---

## Error 4: Line 15, Character 30

**Category**: `cannot_resolve`
**Message**: could not resolve module DataFlow

### Source Context
```ql
     14 | 
>>>  15 |   override predicate isSource(DataFlow::Node source) {
     16 |     source instanceof RemoteFlowSource
```

### LSP Context
**Valid alternatives**: boolean, date, float, int, MyConfig, string, QlBuiltins

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, MyConfig

### Suggested Fix
```ql
// Fix suggestion for: 14 | 
>>>  15 |   override predicate isSource(DataFlow::Node source) {
     16 |     source instanceof RemoteFlowSource
// See candidate fixes above.
```

---

## Error 5: Line 16, Character 22

**Category**: `cannot_resolve`
**Message**: could not resolve type RemoteFlowSource

### Source Context
```ql
     15 |   override predicate isSource(DataFlow::Node source) {
>>>  16 |     source instanceof RemoteFlowSource
     17 |     //               ^^^^^^^^^^^^^^^^
```

### LSP Context
**Valid alternatives**: boolean, date, float, int, MyConfig, string, QlBuiltins

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, MyConfig

### Suggested Fix
```ql
// Fix suggestion for: 15 |   override predicate isSource(DataFlow::Node source) {
>>>  16 |     source instanceof RemoteFlowSource
     17 |     //               ^^^^^^^^^^^^^^^^
// See candidate fixes above.
```

---

## Error 6: Line 21, Character 28

**Category**: `cannot_resolve`
**Message**: could not resolve module DataFlow

### Source Context
```ql
     20 | 
>>>  21 |   override predicate isSink(DataFlow::Node sink) {
     22 |     exists(MethodAccess ma |
```

### LSP Context
**Valid alternatives**: boolean, date, float, int, MyConfig, string, QlBuiltins

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, MyConfig

### Suggested Fix
```ql
// Fix suggestion for: 20 | 
>>>  21 |   override predicate isSink(DataFlow::Node sink) {
     22 |     exists(MethodAccess ma |
// See candidate fixes above.
```

---

## Error 7: Line 22, Character 11

**Category**: `cannot_resolve`
**Message**: could not resolve type MethodAccess

### Source Context
```ql
     21 |   override predicate isSink(DataFlow::Node sink) {
>>>  22 |     exists(MethodAccess ma |
     23 |       ma.getMethod().hasName("executeQuery") and
```

### LSP Context
**Valid alternatives**: sink, boolean, date, float, int, MyConfig, string, getAQlClass

### Candidate Fixes
- Replace with a valid member: sink, boolean, date, float, int

### Suggested Fix
```ql
// Fix suggestion for: 21 |   override predicate isSink(DataFlow::Node sink) {
>>>  22 |     exists(MethodAccess ma |
     23 |       ma.getMethod().hasName("executeQuery") and
// See candidate fixes above.
```

---

## Error 8: Line 29, Character 19

**Category**: `cannot_resolve`
**Message**: could not resolve module DataFlow

### Source Context
```ql
     28 | 
>>>  29 | from MyConfig cfg, DataFlow::Node source, DataFlow::Node sink
     30 | where cfg.hasFlow(source, sink)
```

### LSP Context
**Valid alternatives**: boolean, date, float, int, MyConfig, string, QlBuiltins

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, MyConfig

### Suggested Fix
```ql
// Fix suggestion for: 28 | 
>>>  29 | from MyConfig cfg, DataFlow::Node source, DataFlow::Node sink
     30 | where cfg.hasFlow(source, sink)
// See candidate fixes above.
```

---

## Error 9: Line 29, Character 42

**Category**: `cannot_resolve`
**Message**: could not resolve module DataFlow

### Source Context
```ql
     28 | 
>>>  29 | from MyConfig cfg, DataFlow::Node source, DataFlow::Node sink
     30 | where cfg.hasFlow(source, sink)
```

### LSP Context
**Valid alternatives**: boolean, date, float, int, MyConfig, string, QlBuiltins

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, MyConfig

### Suggested Fix
```ql
// Fix suggestion for: 28 | 
>>>  29 | from MyConfig cfg, DataFlow::Node source, DataFlow::Node sink
     30 | where cfg.hasFlow(source, sink)
// See candidate fixes above.
```

---

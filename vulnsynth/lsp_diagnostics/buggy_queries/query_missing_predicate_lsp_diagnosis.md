# LSP Diagnostic Report for `query_missing_predicate.ql`

**Status**: ❌ 12 Error(s)
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
**Valid alternatives**: MyIncompleteConfig, QlBuiltins

### Candidate Fixes
- Replace with a valid member: MyIncompleteConfig, QlBuiltins

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
      7 | import semmle.code.java.dataflow.FlowSources
```

### LSP Context
**Type/Hover**: **query_missing_predicate**

 Error type: incomplete ConfigSig (missing isBarrier)
 Error type: @kind mismatch with select clause
**Valid alternatives**: MyIncompleteConfig, QlBuiltins

### Candidate Fixes
- Replace with a valid member: MyIncompleteConfig, QlBuiltins
- The expected type is `incomplete`. Make sure the predicate you're calling exists on this type.

### Suggested Fix
```ql
// Fix suggestion for: 5 | import java
>>>   6 | import semmle.code.java.dataflow.DataFlow
      7 | import semmle.code.java.dataflow.FlowSources
// See candidate fixes above.
```

---

## Error 3: Line 7, Character 7

**Category**: `cannot_resolve`
**Message**: could not resolve module semmle.code.java.dataflow.FlowSources

### Source Context
```ql
      6 | import semmle.code.java.dataflow.DataFlow
>>>   7 | import semmle.code.java.dataflow.FlowSources
      8 | 
```

### LSP Context
**Type/Hover**: **query_missing_predicate**

 Error type: incomplete ConfigSig (missing isBarrier)
 Error type: @kind mismatch with select clause
**Valid alternatives**: MyIncompleteConfig, QlBuiltins

### Candidate Fixes
- Replace with a valid member: MyIncompleteConfig, QlBuiltins
- The expected type is `incomplete`. Make sure the predicate you're calling exists on this type.

### Suggested Fix
```ql
// Fix suggestion for: 6 | import semmle.code.java.dataflow.DataFlow
>>>   7 | import semmle.code.java.dataflow.FlowSources
      8 |
// See candidate fixes above.
```

---

## Error 4: Line 25, Character 7

**Category**: `cannot_resolve`
**Message**: could not resolve module MyIncompleteConfig::Flow

### Source Context
```ql
     24 | 
>>>  25 | import MyIncompleteConfig::Flow
     26 | 
```

### LSP Context
**Type/Hover**: **MyIncompleteConfig**
**Valid alternatives**: MyIncompleteConfig, QlBuiltins

### Candidate Fixes
- Replace with a valid member: MyIncompleteConfig, QlBuiltins

### Suggested Fix
```ql
// Fix suggestion for: 24 | 
>>>  25 | import MyIncompleteConfig::Flow
     26 |
// See candidate fixes above.
```

---

## Error 5: Line 9, Character 37

**Category**: `cannot_resolve`
**Message**: could not resolve module DataFlow

### Source Context
```ql
      8 | 
>>>   9 | module MyIncompleteConfig implements DataFlow::ConfigSig {
     10 |   predicate isSource(DataFlow::Node source) {
```

### LSP Context
No LSP context available

### Candidate Fixes

### Suggested Fix
```ql
// Fix suggestion for: 8 | 
>>>   9 | module MyIncompleteConfig implements DataFlow::ConfigSig {
     10 |   predicate isSource(DataFlow::Node source) {
// See candidate fixes above.
```

---

## Error 6: Line 10, Character 21

**Category**: `cannot_resolve`
**Message**: could not resolve module DataFlow

### Source Context
```ql
      9 | module MyIncompleteConfig implements DataFlow::ConfigSig {
>>>  10 |   predicate isSource(DataFlow::Node source) {
     11 |     source instanceof RemoteFlowSource
```

### LSP Context
**Valid alternatives**: boolean, date, float, int, string, QlBuiltins, MyIncompleteConfig

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, string

### Suggested Fix
```ql
// Fix suggestion for: 9 | module MyIncompleteConfig implements DataFlow::ConfigSig {
>>>  10 |   predicate isSource(DataFlow::Node source) {
     11 |     source instanceof RemoteFlowSource
// See candidate fixes above.
```

---

## Error 7: Line 11, Character 22

**Category**: `cannot_resolve`
**Message**: could not resolve type RemoteFlowSource

### Source Context
```ql
     10 |   predicate isSource(DataFlow::Node source) {
>>>  11 |     source instanceof RemoteFlowSource
     12 |   }
```

### LSP Context
**Valid alternatives**: boolean, date, float, int, string, QlBuiltins, MyIncompleteConfig

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, string

### Suggested Fix
```ql
// Fix suggestion for: 10 |   predicate isSource(DataFlow::Node source) {
>>>  11 |     source instanceof RemoteFlowSource
     12 |   }
// See candidate fixes above.
```

---

## Error 8: Line 14, Character 19

**Category**: `cannot_resolve`
**Message**: could not resolve module DataFlow

### Source Context
```ql
     13 | 
>>>  14 |   predicate isSink(DataFlow::Node sink) {
     15 |     exists(MethodAccess ma |
```

### LSP Context
**Valid alternatives**: boolean, date, float, int, string, QlBuiltins, MyIncompleteConfig

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, string

### Suggested Fix
```ql
// Fix suggestion for: 13 | 
>>>  14 |   predicate isSink(DataFlow::Node sink) {
     15 |     exists(MethodAccess ma |
// See candidate fixes above.
```

---

## Error 9: Line 15, Character 11

**Category**: `cannot_resolve`
**Message**: could not resolve type MethodAccess

### Source Context
```ql
     14 |   predicate isSink(DataFlow::Node sink) {
>>>  15 |     exists(MethodAccess ma |
     16 |       ma.getMethod().hasName("executeQuery") and
```

### LSP Context
**Valid alternatives**: sink, boolean, date, float, int, string, any, none

### Candidate Fixes
- Replace with a valid member: sink, boolean, date, float, int

### Suggested Fix
```ql
// Fix suggestion for: 14 |   predicate isSink(DataFlow::Node sink) {
>>>  15 |     exists(MethodAccess ma |
     16 |       ma.getMethod().hasName("executeQuery") and
// See candidate fixes above.
```

---

## Error 10: Line 27, Character 5

**Category**: `cannot_resolve`
**Message**: could not resolve module MyIncompleteConfig::Flow

### Source Context
```ql
     26 | 
>>>  27 | from MyIncompleteConfig::Flow::PathNode source, MyIncompleteConfig::Flow::PathNode sink
     28 | where MyIncompleteConfig::Flow::flowPath(source, sink)
```

### LSP Context
**Type/Hover**: **MyIncompleteConfig**
**Valid alternatives**: boolean, date, float, int, string, MyIncompleteConfig, QlBuiltins, where

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, string

### Suggested Fix
```ql
// Fix suggestion for: 26 | 
>>>  27 | from MyIncompleteConfig::Flow::PathNode source, MyIncompleteConfig::Flow::PathNode sink
     28 | where MyIncompleteConfig::Flow::flowPath(source, sink)
// See candidate fixes above.
```

---

## Error 11: Line 27, Character 48

**Category**: `cannot_resolve`
**Message**: could not resolve module MyIncompleteConfig::Flow

### Source Context
```ql
     26 | 
>>>  27 | from MyIncompleteConfig::Flow::PathNode source, MyIncompleteConfig::Flow::PathNode sink
     28 | where MyIncompleteConfig::Flow::flowPath(source, sink)
```

### LSP Context
**Type/Hover**: **MyIncompleteConfig**
**Valid alternatives**: boolean, date, float, int, string, MyIncompleteConfig, QlBuiltins

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, string

### Suggested Fix
```ql
// Fix suggestion for: 26 | 
>>>  27 | from MyIncompleteConfig::Flow::PathNode source, MyIncompleteConfig::Flow::PathNode sink
     28 | where MyIncompleteConfig::Flow::flowPath(source, sink)
// See candidate fixes above.
```

---

## Error 12: Line 28, Character 6

**Category**: `cannot_resolve`
**Message**: could not resolve module MyIncompleteConfig::Flow

### Source Context
```ql
     27 | from MyIncompleteConfig::Flow::PathNode source, MyIncompleteConfig::Flow::PathNode sink
>>>  28 | where MyIncompleteConfig::Flow::flowPath(source, sink)
     29 | select sink.getNode(), source, sink, "$@", source, "source"
```

### LSP Context
**Type/Hover**: **MyIncompleteConfig**
**Valid alternatives**: source, sink, any, none, MyIncompleteConfig, QlBuiltins

### Candidate Fixes
- Replace with a valid member: source, sink, any, none, MyIncompleteConfig

### Suggested Fix
```ql
// Fix suggestion for: 27 | from MyIncompleteConfig::Flow::PathNode source, MyIncompleteConfig::Flow::PathNode sink
>>>  28 | where MyIncompleteConfig::Flow::flowPath(source, sink)
     29 | select sink.getNode(), source, sink, "$@", source, "source"
// See candidate fixes above.
```

---

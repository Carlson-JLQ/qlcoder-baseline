# LSP Diagnostic Report for `query_single_error.ql`

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
**Valid alternatives**: TestConfig, QlBuiltins

### Candidate Fixes
- Replace with a valid member: TestConfig, QlBuiltins

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
**Type/Hover**: **query_single_error**

kind
: path-problem
 Single intentional error: getBadName() does not exist on Method


**Valid alternatives**: TestConfig, QlBuiltins

### Candidate Fixes
- Replace with a valid member: TestConfig, QlBuiltins

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
**Type/Hover**: **query_single_error**

kind
: path-problem
 Single intentional error: getBadName() does not exist on Method


**Valid alternatives**: TestConfig, QlBuiltins

### Candidate Fixes
- Replace with a valid member: TestConfig, QlBuiltins

### Suggested Fix
```ql
// Fix suggestion for: 6 | import semmle.code.java.dataflow.DataFlow
>>>   7 | import semmle.code.java.dataflow.FlowSources
      8 |
// See candidate fixes above.
```

---

## Error 4: Line 19, Character 7

**Category**: `cannot_resolve`
**Message**: could not resolve module TestConfig::Flow

### Source Context
```ql
     18 | 
>>>  19 | import TestConfig::Flow
     20 | 
```

### LSP Context
**Type/Hover**: **TestConfig**
**Valid alternatives**: TestConfig, QlBuiltins

### Candidate Fixes
- Replace with a valid member: TestConfig, QlBuiltins

### Suggested Fix
```ql
// Fix suggestion for: 18 | 
>>>  19 | import TestConfig::Flow
     20 |
// See candidate fixes above.
```

---

## Error 5: Line 9, Character 29

**Category**: `cannot_resolve`
**Message**: could not resolve module DataFlow

### Source Context
```ql
      8 | 
>>>   9 | module TestConfig implements DataFlow::ConfigSig {
     10 |   predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }
```

### LSP Context
No LSP context available

### Candidate Fixes

### Suggested Fix
```ql
// Fix suggestion for: 8 | 
>>>   9 | module TestConfig implements DataFlow::ConfigSig {
     10 |   predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }
// See candidate fixes above.
```

---

## Error 6: Line 10, Character 21

**Category**: `cannot_resolve`
**Message**: could not resolve module DataFlow

### Source Context
```ql
      9 | module TestConfig implements DataFlow::ConfigSig {
>>>  10 |   predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }
     11 |   predicate isSink(DataFlow::Node sink) {
```

### LSP Context
**Valid alternatives**: boolean, date, float, int, string, QlBuiltins, TestConfig

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, string

### Suggested Fix
```ql
// Fix suggestion for: 9 | module TestConfig implements DataFlow::ConfigSig {
>>>  10 |   predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }
     11 |   predicate isSink(DataFlow::Node sink) {
// See candidate fixes above.
```

---

## Error 7: Line 10, Character 64

**Category**: `cannot_resolve`
**Message**: could not resolve type RemoteFlowSource

### Source Context
```ql
      9 | module TestConfig implements DataFlow::ConfigSig {
>>>  10 |   predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }
     11 |   predicate isSink(DataFlow::Node sink) {
```

### LSP Context
**Valid alternatives**: boolean, date, float, int, string, QlBuiltins, TestConfig

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, string

### Suggested Fix
```ql
// Fix suggestion for: 9 | module TestConfig implements DataFlow::ConfigSig {
>>>  10 |   predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }
     11 |   predicate isSink(DataFlow::Node sink) {
// See candidate fixes above.
```

---

## Error 8: Line 11, Character 19

**Category**: `cannot_resolve`
**Message**: could not resolve module DataFlow

### Source Context
```ql
     10 |   predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }
>>>  11 |   predicate isSink(DataFlow::Node sink) {
     12 |     exists(MethodAccess ma |
```

### LSP Context
**Valid alternatives**: boolean, date, float, int, string, QlBuiltins, TestConfig

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, string

### Suggested Fix
```ql
// Fix suggestion for: 10 |   predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }
>>>  11 |   predicate isSink(DataFlow::Node sink) {
     12 |     exists(MethodAccess ma |
// See candidate fixes above.
```

---

## Error 9: Line 12, Character 11

**Category**: `cannot_resolve`
**Message**: could not resolve type MethodAccess

### Source Context
```ql
     11 |   predicate isSink(DataFlow::Node sink) {
>>>  12 |     exists(MethodAccess ma |
     13 |       ma.getMethod().getBadName() = "execute" and
```

### LSP Context
**Valid alternatives**: sink, boolean, date, float, int, string, any, none

### Candidate Fixes
- Replace with a valid member: sink, boolean, date, float, int

### Suggested Fix
```ql
// Fix suggestion for: 11 |   predicate isSink(DataFlow::Node sink) {
>>>  12 |     exists(MethodAccess ma |
     13 |       ma.getMethod().getBadName() = "execute" and
// See candidate fixes above.
```

---

## Error 10: Line 21, Character 5

**Category**: `cannot_resolve`
**Message**: could not resolve module TestConfig::Flow

### Source Context
```ql
     20 | 
>>>  21 | from TestConfig::Flow::PathNode source, TestConfig::Flow::PathNode sink
     22 | where TestConfig::Flow::flowPath(source, sink)
```

### LSP Context
**Type/Hover**: **TestConfig**
**Valid alternatives**: boolean, date, float, int, string, TestConfig, QlBuiltins, where

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, string

### Suggested Fix
```ql
// Fix suggestion for: 20 | 
>>>  21 | from TestConfig::Flow::PathNode source, TestConfig::Flow::PathNode sink
     22 | where TestConfig::Flow::flowPath(source, sink)
// See candidate fixes above.
```

---

## Error 11: Line 21, Character 40

**Category**: `cannot_resolve`
**Message**: could not resolve module TestConfig::Flow

### Source Context
```ql
     20 | 
>>>  21 | from TestConfig::Flow::PathNode source, TestConfig::Flow::PathNode sink
     22 | where TestConfig::Flow::flowPath(source, sink)
```

### LSP Context
**Type/Hover**: **TestConfig**
**Valid alternatives**: boolean, date, float, int, string, TestConfig, QlBuiltins

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, string

### Suggested Fix
```ql
// Fix suggestion for: 20 | 
>>>  21 | from TestConfig::Flow::PathNode source, TestConfig::Flow::PathNode sink
     22 | where TestConfig::Flow::flowPath(source, sink)
// See candidate fixes above.
```

---

## Error 12: Line 22, Character 6

**Category**: `cannot_resolve`
**Message**: could not resolve module TestConfig::Flow

### Source Context
```ql
     21 | from TestConfig::Flow::PathNode source, TestConfig::Flow::PathNode sink
>>>  22 | where TestConfig::Flow::flowPath(source, sink)
     23 | select sink.getNode(), source, sink, "$@", source, "source"
```

### LSP Context
**Type/Hover**: **TestConfig**
**Valid alternatives**: source, sink, any, none, TestConfig, QlBuiltins

### Candidate Fixes
- Replace with a valid member: source, sink, any, none, TestConfig

### Suggested Fix
```ql
// Fix suggestion for: 21 | from TestConfig::Flow::PathNode source, TestConfig::Flow::PathNode sink
>>>  22 | where TestConfig::Flow::flowPath(source, sink)
     23 | select sink.getNode(), source, sink, "$@", source, "source"
// See candidate fixes above.
```

---

# LSP Diagnostic Report for `query_wrong_method.ql`

**Status**: ❌ 13 Error(s)
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
**Valid alternatives**: MyConfig, QlBuiltins

### Candidate Fixes
- Replace with a valid member: MyConfig, QlBuiltins

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
**Type/Hover**: **query_wrong_method**

 Error type: wrong method name (getParam vs getParameter)
 Error type: wrong predicate (getFoo doesn't exist on Method)
**Valid alternatives**: MyConfig, QlBuiltins

### Candidate Fixes
- Replace with a valid member: MyConfig, QlBuiltins
- The expected type is `wrong`. Make sure the predicate you're calling exists on this type.

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
**Type/Hover**: **query_wrong_method**

 Error type: wrong method name (getParam vs getParameter)
 Error type: wrong predicate (getFoo doesn't exist on Method)
**Valid alternatives**: MyConfig, QlBuiltins

### Candidate Fixes
- Replace with a valid member: MyConfig, QlBuiltins
- The expected type is `wrong`. Make sure the predicate you're calling exists on this type.

### Suggested Fix
```ql
// Fix suggestion for: 6 | import semmle.code.java.dataflow.DataFlow
>>>   7 | import semmle.code.java.dataflow.FlowSources
      8 |
// See candidate fixes above.
```

---

## Error 4: Line 27, Character 7

**Category**: `cannot_resolve`
**Message**: could not resolve module MyConfig::Flow

### Source Context
```ql
     26 | 
>>>  27 | import MyConfig::Flow
     28 | 
```

### LSP Context
**Type/Hover**: **MyConfig**
**Valid alternatives**: MyConfig, QlBuiltins

### Candidate Fixes
- Replace with a valid member: MyConfig, QlBuiltins

### Suggested Fix
```ql
// Fix suggestion for: 26 | 
>>>  27 | import MyConfig::Flow
     28 |
// See candidate fixes above.
```

---

## Error 5: Line 9, Character 27

**Category**: `cannot_resolve`
**Message**: could not resolve module DataFlow

### Source Context
```ql
      8 | 
>>>   9 | module MyConfig implements DataFlow::ConfigSig {
     10 |   predicate isSource(DataFlow::Node source) {
```

### LSP Context
No LSP context available

### Candidate Fixes

### Suggested Fix
```ql
// Fix suggestion for: 8 | 
>>>   9 | module MyConfig implements DataFlow::ConfigSig {
     10 |   predicate isSource(DataFlow::Node source) {
// See candidate fixes above.
```

---

## Error 6: Line 10, Character 21

**Category**: `cannot_resolve`
**Message**: could not resolve module DataFlow

### Source Context
```ql
      9 | module MyConfig implements DataFlow::ConfigSig {
>>>  10 |   predicate isSource(DataFlow::Node source) {
     11 |     source instanceof RemoteFlowSource and
```

### LSP Context
**Valid alternatives**: boolean, date, float, int, string, QlBuiltins, MyConfig

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, string

### Suggested Fix
```ql
// Fix suggestion for: 9 | module MyConfig implements DataFlow::ConfigSig {
>>>  10 |   predicate isSource(DataFlow::Node source) {
     11 |     source instanceof RemoteFlowSource and
// See candidate fixes above.
```

---

## Error 7: Line 11, Character 22

**Category**: `cannot_resolve`
**Message**: could not resolve type RemoteFlowSource

### Source Context
```ql
     10 |   predicate isSource(DataFlow::Node source) {
>>>  11 |     source instanceof RemoteFlowSource and
     12 |     source.asExpr().(MethodAccess).getMethod().getName() = "getParam"
```

### LSP Context
**Valid alternatives**: boolean, date, float, int, string, QlBuiltins, MyConfig

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, string

### Suggested Fix
```ql
// Fix suggestion for: 10 |   predicate isSource(DataFlow::Node source) {
>>>  11 |     source instanceof RemoteFlowSource and
     12 |     source.asExpr().(MethodAccess).getMethod().getName() = "getParam"
// See candidate fixes above.
```

---

## Error 8: Line 12, Character 21

**Category**: `cannot_resolve`
**Message**: could not resolve type MethodAccess

### Source Context
```ql
     11 |     source instanceof RemoteFlowSource and
>>>  12 |     source.asExpr().(MethodAccess).getMethod().getName() = "getParam"
     13 |     //                                                              ^^^^^^^^
```

### LSP Context
**Valid alternatives**: boolean, date, float, int, string, QlBuiltins, MyConfig

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, string

### Suggested Fix
```ql
// Fix suggestion for: 11 |     source instanceof RemoteFlowSource and
>>>  12 |     source.asExpr().(MethodAccess).getMethod().getName() = "getParam"
     13 |     //                                                              ^^^^^^^^
// See candidate fixes above.
```

---

## Error 9: Line 18, Character 19

**Category**: `cannot_resolve`
**Message**: could not resolve module DataFlow

### Source Context
```ql
     17 | 
>>>  18 |   predicate isSink(DataFlow::Node sink) {
     19 |     exists(MethodCall mc |
```

### LSP Context
**Valid alternatives**: boolean, date, float, int, string, QlBuiltins, MyConfig

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, string

### Suggested Fix
```ql
// Fix suggestion for: 17 | 
>>>  18 |   predicate isSink(DataFlow::Node sink) {
     19 |     exists(MethodCall mc |
// See candidate fixes above.
```

---

## Error 10: Line 19, Character 11

**Category**: `cannot_resolve`
**Message**: could not resolve type MethodCall

### Source Context
```ql
     18 |   predicate isSink(DataFlow::Node sink) {
>>>  19 |     exists(MethodCall mc |
     20 |       mc.getMethod().getFoo() = "executeQuery" and
```

### LSP Context
**Valid alternatives**: sink, boolean, date, float, int, string, any, none

### Candidate Fixes
- Replace with a valid member: sink, boolean, date, float, int

### Suggested Fix
```ql
// Fix suggestion for: 18 |   predicate isSink(DataFlow::Node sink) {
>>>  19 |     exists(MethodCall mc |
     20 |       mc.getMethod().getFoo() = "executeQuery" and
// See candidate fixes above.
```

---

## Error 11: Line 29, Character 5

**Category**: `cannot_resolve`
**Message**: could not resolve module MyConfig::Flow

### Source Context
```ql
     28 | 
>>>  29 | from MyConfig::Flow::PathNode source, MyConfig::Flow::PathNode sink
     30 | where MyConfig::Flow::flowPath(source, sink)
```

### LSP Context
**Type/Hover**: **MyConfig**
**Valid alternatives**: boolean, date, float, int, string, MyConfig, QlBuiltins, where

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, string

### Suggested Fix
```ql
// Fix suggestion for: 28 | 
>>>  29 | from MyConfig::Flow::PathNode source, MyConfig::Flow::PathNode sink
     30 | where MyConfig::Flow::flowPath(source, sink)
// See candidate fixes above.
```

---

## Error 12: Line 29, Character 38

**Category**: `cannot_resolve`
**Message**: could not resolve module MyConfig::Flow

### Source Context
```ql
     28 | 
>>>  29 | from MyConfig::Flow::PathNode source, MyConfig::Flow::PathNode sink
     30 | where MyConfig::Flow::flowPath(source, sink)
```

### LSP Context
**Type/Hover**: **MyConfig**
**Valid alternatives**: boolean, date, float, int, string, MyConfig, QlBuiltins

### Candidate Fixes
- Replace with a valid member: boolean, date, float, int, string

### Suggested Fix
```ql
// Fix suggestion for: 28 | 
>>>  29 | from MyConfig::Flow::PathNode source, MyConfig::Flow::PathNode sink
     30 | where MyConfig::Flow::flowPath(source, sink)
// See candidate fixes above.
```

---

## Error 13: Line 30, Character 6

**Category**: `cannot_resolve`
**Message**: could not resolve module MyConfig::Flow

### Source Context
```ql
     29 | from MyConfig::Flow::PathNode source, MyConfig::Flow::PathNode sink
>>>  30 | where MyConfig::Flow::flowPath(source, sink)
     31 | select sink.getNode(), source, sink, "$@ flows to $@", source, "source", sink, "sink"
```

### LSP Context
**Type/Hover**: **MyConfig**
**Valid alternatives**: source, sink, any, none, MyConfig, QlBuiltins

### Candidate Fixes
- Replace with a valid member: source, sink, any, none, MyConfig

### Suggested Fix
```ql
// Fix suggestion for: 29 | from MyConfig::Flow::PathNode source, MyConfig::Flow::PathNode sink
>>>  30 | where MyConfig::Flow::flowPath(source, sink)
     31 | select sink.getNode(), source, sink, "$@ flows to $@", source, "source", sink, "sink"
// See candidate fixes above.
```

---

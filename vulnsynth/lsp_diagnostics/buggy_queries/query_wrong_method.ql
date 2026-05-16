/**
 * Error type: wrong method name (getParam vs getParameter)
 * Error type: wrong predicate (getFoo doesn't exist on Method)
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource and
    source.asExpr().(MethodAccess).getMethod().getName() = "getParam"
    //                                                              ^^^^^^^^
    // ERROR: getName() works, but getMethod() returns a Method,
    // and the intent was to check for HTTP parameter access
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      mc.getMethod().getFoo() = "executeQuery" and
      //                ^^^^^^ ERROR: getFoo() does not exist on Method
      sink.asExpr() = mc
    )
  }
}

import MyConfig::Flow

from MyConfig::Flow::PathNode source, MyConfig::Flow::PathNode sink
where MyConfig::Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "$@ flows to $@", source, "source", sink, "sink"

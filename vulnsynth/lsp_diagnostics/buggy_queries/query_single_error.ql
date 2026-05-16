/**
 * @kind path-problem
 * Single intentional error: getBadName() does not exist on Method
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

module TestConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().getBadName() = "execute" and
      sink.asExpr() = ma
    )
  }
}

import TestConfig::Flow

from TestConfig::Flow::PathNode source, TestConfig::Flow::PathNode sink
where TestConfig::Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "$@", source, "source"

/**
 * Error type: multiple errors (combined: wrong method, missing import, type mistake)
 * Represents a typical first-draft LLM output
 */
import java
import semmle.code.java.dataflow.DataFlow

class SqlInjectionConfig extends DataFlow::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof HttpServletRequest and
    //               ^^^^^^^^^^^^^^^^ ERROR: wrong type, should be a RemoteFlowSource
    source.asExpr().getParameter("userId")
    //               ^^^^^^^^^^^^ ERROR: Expr has no getParameter
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Statement stmt |
      stmt.getSqlString() = sink.asExpr() and
      //    ^^^^^^^^^^^^^ ERROR: Statement has no getSqlString
      stmt instanceof ExecuteStatement
    )
  }
}

from SqlInjectionConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, source, sink, "SQL injection from $@ to $@", source, "source", sink, "sink"

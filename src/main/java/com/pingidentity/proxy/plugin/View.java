package com.pingidentity.proxy.plugin;

import com.unboundid.directory.sdk.common.operation.UpdatableSearchRequest;
import com.unboundid.directory.sdk.common.operation.UpdatableSearchResult;
import com.unboundid.directory.sdk.common.types.ActiveSearchOperationContext;
import com.unboundid.directory.sdk.common.types.LogSeverity;
import com.unboundid.directory.sdk.ds.api.Plugin;
import com.unboundid.directory.sdk.ds.config.PluginConfig;
import com.unboundid.directory.sdk.ds.types.DirectoryServerContext;
import com.unboundid.directory.sdk.ds.types.PreParsePluginResult;
import com.unboundid.ldap.sdk.*;
import com.unboundid.scim2.common.filters.FilterType;
import com.unboundid.util.args.BooleanValueArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.StringArgument;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by arnaudlacour on 5/19/17.
 */
public class View extends Plugin
{
    private static final String ARG_NAME_VIEW_BASE = "view-base-dn";
    
    // FIRST PHASE
    private static final String ARG_NAME_FIRST_PHASE_BASE = "first-phase-base-dn";
    private static final String ARG_NAME_FIRST_ATTRIBUTE = "first-phase-attribute";
    private static final String ARG_NAME_FIRST_PHASE_MUST_BE_UNIQUE = "first-phase-must-be-unique";
    
    // SECOND PHASE
    private static final String ARG_NAME_SECOND_PHASE_BASE = "second-phase-base-dn";
    private static final String ARG_NAME_SECOND_PHASE_ATTRIBUTE = "second-phase-attribute";
    private static final String ARG_NAME_SECOND_PHASE_CONSTRAINT = "second-phase-constraint";
    
    
    private DN baseDN;
    private DirectoryServerContext serverContext;
    private PluginConfig config;
    private DN firstPhaseBaseDN;
    private List<String> firstPhaseAttributes;
    private Boolean firstPhaseMustBeUnique;
    private DN secondPhaseBaseDN;
    private List<String> secondPhaseAttributes;
    private Filter secondPhaseConstraint;
    
    // <o Comcast><ou views><ou UDB><ou billingv1>
    @Override
    public String getExtensionName()
    {
        return "Proxy Plugin View";
    }
    
    @Override
    public String[] getExtensionDescription()
    {
        return new String[]{"A plugin that provides an single endpoint for complex traversal queries"};
    }
    
    public void defineConfigArguments(com.unboundid.util.args.ArgumentParser parser)
            throws com.unboundid.util.args.ArgumentException
    {
        /*
        Define the argument to provide the base DN for which this view should execute
         */
        parser.addArgument(
                new DNArgument(null, ARG_NAME_VIEW_BASE, true, 1,
                        "{DN}",
                        "The base DN for which to execute this plugin"));
        /*
        Define the argument to provide the base for the first phase
         */
        parser.addArgument(
                new DNArgument(null, ARG_NAME_FIRST_PHASE_BASE, true, 1,
                        "{DN}",
                        "The base DN for the first phase"));
        /*
        Define the argument to provide the base for the first phase
         */
        parser.addArgument(
                new StringArgument(null, ARG_NAME_FIRST_ATTRIBUTE, false, 0,
                        "{attribute}",
                        "The list of attributes to fetch for the first phase"));
        
        /*
        Define the argument to provide to indicate whether the first phase result should be unique
         */
        parser.addArgument(new BooleanValueArgument(null, ARG_NAME_FIRST_PHASE_MUST_BE_UNIQUE,
                false, "{true|false}",
                "Whether to throw an exception if the first phase is not unique"));

        /*
        Define the argument to provide the base for the second phase
         */
        parser.addArgument(
                new DNArgument(null, ARG_NAME_SECOND_PHASE_BASE, true, 1,
                        "{DN}",
                        "The base DN for the second phase"));
        /*
        Define the argument to provide the base for the second phase
         */
        parser.addArgument(
                new StringArgument(null, ARG_NAME_SECOND_PHASE_ATTRIBUTE, false, 0,
                        "{attribute}",
                        "The list of attributes to fetch for the second phase"));
        
        /*
        Define the argument to provide an additional filter to pare down results in the second phase
         */
        parser.addArgument(new FileArgument(null, ARG_NAME_SECOND_PHASE_CONSTRAINT, false, 1, "{filter}",
                "A filter to pare down results in the second phase"));
    }
    
    public ResultCode applyConfiguration(PluginConfig config,
                                         com.unboundid.util.args.ArgumentParser parser,
                                         java.util.List<java.lang.String> adminActionsRequired,
                                         java.util.List<java.lang.String> messages)
    {
        baseDN = parser.getDNArgument(ARG_NAME_VIEW_BASE).getValue();

        firstPhaseBaseDN = parser.getDNArgument(ARG_NAME_FIRST_PHASE_BASE).getValue();
        firstPhaseAttributes = parser.getStringArgument(ARG_NAME_FIRST_ATTRIBUTE).getValues();
        firstPhaseMustBeUnique = parser.getBooleanValueArgument(ARG_NAME_FIRST_PHASE_MUST_BE_UNIQUE).getValue();
        
        secondPhaseBaseDN = parser.getDNArgument(ARG_NAME_SECOND_PHASE_BASE).getValue();
        secondPhaseAttributes = parser.getStringArgument(ARG_NAME_SECOND_PHASE_ATTRIBUTE).getValues();
        secondPhaseConstraint = parser.getFilterArgument(ARG_NAME_SECOND_PHASE_CONSTRAINT).getValue();
        
        return ResultCode.SUCCESS;
    }
    
    public void initializePlugin(DirectoryServerContext serverContext,
                                 PluginConfig config,
                                 com.unboundid.util.args.ArgumentParser parser)
            throws com.unboundid.ldap.sdk.LDAPException
    {
        this.serverContext = serverContext;
        this.config = config;
        
        List<String> actions = new ArrayList<>();
        List<String> messages = new ArrayList<>();
        
        ResultCode result = applyConfiguration(config, parser, actions, messages);
        if (result != ResultCode.SUCCESS)
        {
            serverContext.logMessage(LogSeverity.FATAL_ERROR, "Configuration could not be successfully applied");
        }
    }
    
    public PreParsePluginResult doPreParse(ActiveSearchOperationContext operationContext,
                                           UpdatableSearchRequest request,
                                           UpdatableSearchResult result)
    {
        PreParsePluginResult pluginResult = new PreParsePluginResult(false, false, true, true);
        
        Filter filter = request.getFilter();
        if (filter != null && FilterType.EQUAL.equals(filter.getFilterType()))
        {
            // This will get you the attribute name from the filter
            String Attribute = filter.getAttributeName();
            
            // This will get you the value associated with the attribute name in the filter
            String Value = filter.getAssertionValue();
            
            
            try
            {
                SearchRequest firstPhaseSearcRequest = new SearchRequest(firstPhaseBaseDN.toString(), SearchScope.SUB, filter, null);
                SearchResult firstPhaseSearchResult = operationContext.getInternalUserConnection().search(firstPhaseSearcRequest);
                if (firstPhaseSearchResult.getResultCode() == ResultCode.SUCCESS)
                {
                    if (firstPhaseMustBeUnique && firstPhaseSearchResult.getEntryCount() > 1)
                    {
                        result.setDiagnosticMessage("This view is configured to require that the request yield one or" +
                                " zero result for the first phase. Entries found in first stage: " + firstPhaseSearchResult.getEntryCount());
                        result.setResultCode(ResultCode.CONSTRAINT_VIOLATION);
                        return pluginResult;
                    }
                    
                    List<Filter> orFilterComponentns = new ArrayList<>();
                    for (SearchResultEntry e : firstPhaseSearchResult.getSearchEntries())
                    {
                        Attribute attr = e.getAttribute("cstPhysicalResourceLinks");
                        for (String value : attr.getValues())
                        {
                            orFilterComponentns.add(Filter.createEqualityFilter("cstResourceGuid", value));
                        }
                        operationContext.sendSearchEntry(e);
                    }
                    Filter secondPhaseFilter = Filter.createANDFilter(secondPhaseConstraint,Filter.createORFilter(orFilterComponentns));
                    
    
                    SearchResult secondPhaseSearchResult = operationContext.getInternalUserConnection().search
                            (secondPhaseBaseDN.toString(), SearchScope.SUB, secondPhaseFilter, null);
                    for (SearchResultEntry e: secondPhaseSearchResult.getSearchEntries())
                    {
                        operationContext.sendSearchEntry(e);
                    }
                }
            } catch (LDAPException e)
            {
                result.setResultCode(e.getResultCode());
                result.setDiagnosticMessage(e.getDiagnosticMessage());
                result.setAdditionalLogMessage(e.getExceptionMessage());
            }
        }
        return pluginResult;
    }
}

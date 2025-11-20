package hunts

import (
	"context"
	"errors"
	"slices"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/cloudvelo/constants"
	cveloapi "www.velocidex.com/golang/cloudvelo/schema/api"
	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/api/proto"
	configproto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/file_store"
	"www.velocidex.com/golang/velociraptor/paths"
	artifactpaths "www.velocidex.com/golang/velociraptor/paths/artifacts"
	"www.velocidex.com/golang/velociraptor/result_sets"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/services/hunt_dispatcher"
	"www.velocidex.com/golang/velociraptor/vql"
	vqlsubsystem "www.velocidex.com/golang/velociraptor/vql"
	vqlutils "www.velocidex.com/golang/velociraptor/vql/utils"
	"www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"

	_ "www.velocidex.com/golang/velociraptor/vql/server/hunts"
)

type HuntResultsPluginArgs struct {
	Artifact string   `vfilter:"optional,field=artifact,doc=The artifact to retrieve"`
	Source   string   `vfilter:"optional,field=source,doc=An optional source within the artifact."`
	HuntId   string   `vfilter:"required,field=hunt_id,doc=The hunt id to read."`
	Brief    bool     `vfilter:"optional,field=brief,doc=If set we return less columns (deprecated)."`
	Orgs     []string `vfilter:"optional,field=orgs,doc=If set we combine results from all orgs."`
}

type HuntResultsPlugin struct{}

func (h HuntResultsPlugin) Call(
	ctx context.Context,
	scope vfilter.Scope,
	args *ordereddict.Dict) <-chan vfilter.Row {
	outputChan := make(chan vfilter.Row)

	go func() {
		defer close(outputChan)
		defer vqlsubsystem.RegisterMonitor(ctx, "hunt_results", args)()

		err := vqlsubsystem.CheckAccess(scope, acls.READ_RESULTS)
		if err != nil {
			scope.Log("hunt_results: %s", err)
			return
		}

		arg := &HuntResultsPluginArgs{}
		err = arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
		if err != nil {
			scope.Log("hunt_results: %v", err)
			return
		}

		err = services.RequireFrontend()
		if err != nil {
			scope.Log("hunt_results: %v", err)
			return
		}

		configObj, ok := vqlsubsystem.GetServerConfig(scope)
		if !ok {
			scope.Log("hunt_results: Command can only run on the server")
			return
		}

		err = verifyArgs(arg, configObj, scope, ctx)
		if err != nil {
			scope.Log("hunt_results: %v", err)
			return
		}

		principal := vqlsubsystem.GetPrincipal(scope)

		orgManager, err := services.GetOrgManager()
		if err != nil {
			return
		}

		for _, orgId := range arg.Orgs {
			orgConfigObj, err := orgManager.GetOrgConfig(orgId)
			if err != nil {
				continue
			}

			// Make sure the principal has read access in this org.
			permissions := acls.READ_RESULTS
			perm, err := services.CheckAccess(
				orgConfigObj, principal, permissions)
			if !perm || err != nil {
				continue
			}

			huntDispatcher, err := services.GetHuntDispatcher(orgConfigObj)
			if err != nil {
				return
			}

			options := services.FlowSearchOptions{BasicInformation: true}
			flowChan, _, err := huntDispatcher.GetFlows(
				ctx, orgConfigObj, options, scope, arg.HuntId, 0)
			if err != nil {
				// If there are no flows in this hunt - it is not an
				// error it just means no results.
				return
			}

			// Exhaust flow channel and hold everything in mem for subsequent batching
			var flows []*proto.FlowDetails
			for flow := range flowChan {
				flows = append(flows, flow)
			}

			clientFqdns, err := associateClientIdAndFqdn(ctx, configObj, flows)
			if err != nil {
				scope.Log("hunt_results: %v", err)
				return
			}

			for _, flowDetail := range flows {
				// Read individual flow's results.
				pathManager, err := artifactpaths.NewArtifactPathManager(
					ctx, orgConfigObj,
					flowDetail.Context.ClientId,
					flowDetail.Context.SessionId,
					arg.Artifact)
				if err != nil {
					continue
				}

				fileStoreFactory := file_store.GetFileStore(orgConfigObj)

				reader, err := result_sets.NewResultSetReader(
					fileStoreFactory, pathManager.Path())
				if err != nil {
					continue
				}

				// Read each result set and emit it
				// with some extra columns for
				// context.
				for row := range reader.Rows(ctx) {
					row.Set("FlowId", flowDetail.Context.SessionId).
						Set("ClientId", flowDetail.Context.ClientId).
						Set("_OrgId", orgId).
						Set("Fqdn", clientFqdns[flowDetail.Context.ClientId])

					select {
					case <-ctx.Done():
						return
					case outputChan <- row:
					}
				}
			}
		}
	}()

	return outputChan
}

// Retrieve FQDNs with batched requests
func associateClientIdAndFqdn(ctx context.Context, configObj *configproto.Config, flows []*proto.FlowDetails) (map[string]string, error) {
	var fqdnAssociation map[string]string

	for flowBatch := range slices.Chunk(flows, constants.OPENSEARCH_DOCUMENT_LIMIT) {
		var clientIds []string
		for _, flow := range flowBatch {
			clientIds = append(clientIds, flow.Context.ClientId)
		}
		records, err := cveloapi.GetMultipleClients(ctx, configObj, clientIds)
		if err != nil {
			return nil, err
		}

		for _, record := range records {
			fqdnAssociation[record.ClientId] = record.Hostname
		}

	}

	return fqdnAssociation, nil
}

func verifyArgs(arg *HuntResultsPluginArgs, configObj *configproto.Config, scope vfilter.Scope, ctx context.Context) error {
	// If no artifact is specified, get the first one from the hunt.
	if arg.Artifact == "" {
		huntDispatcherService, err := services.GetHuntDispatcher(configObj)
		if err != nil {
			return err
		}

		huntObj, pres := huntDispatcherService.GetHunt(ctx, arg.HuntId)
		if !pres {
			return errors.New("hunt not found")
		}

		hunt_dispatcher.FindCollectedArtifacts(ctx, configObj, huntObj)
		if len(huntObj.Artifacts) == 0 {
			return errors.New("no artifacts in hunt")
		}

		if arg.Source == "" {
			arg.Artifact, arg.Source = paths.SplitFullSourceName(
				huntObj.Artifacts[0])
		}

		// If the source is not specified find the first named
		// source from the artifact definition.
		if arg.Source == "" {
			repo, err := vqlutils.GetRepository(scope)
			if err == nil {
				artifactDef, ok := repo.Get(ctx, configObj, arg.Artifact)
				if ok {
					for _, source := range artifactDef.Sources {
						if source.Name != "" {
							arg.Source = source.Name
							break
						}
					}
				}
			}
		}
	}

	if arg.Source != "" {
		arg.Artifact += "/" + arg.Source
	}

	if len(arg.Orgs) == 0 {
		arg.Orgs = append(arg.Orgs, configObj.OrgId)
	}
	return nil
}

func (h HuntResultsPlugin) Info(scope vfilter.Scope, typeMap *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name:     "hunt_results",
		Doc:      "Retrieve the results of a hunt.",
		ArgType:  typeMap.AddType(scope, &HuntResultsPluginArgs{}),
		Metadata: vql.VQLMetadata().Permissions(acls.READ_RESULTS).Build(),
	}
}

func init() {
	vqlsubsystem.OverridePlugin(&HuntResultsPlugin{})
}

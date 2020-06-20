import {
  TumauServer,
  Chemin,
  CheminParam,
  Middleware,
  CorsPackage,
  JsonPackage,
  InvalidResponseToHttpError,
  RouterPackage,
  Route,
  JsonResponse,
  RouterConsumer,
  RequestConsumer,
  HttpError,
} from 'tumau';
import * as RT from 'runtypes';
import { SyncData, MerkleTree, Kiip, KiipDatabase } from '@kiip/core';
import { nanoid } from 'nanoid';
import { RuntypesValidator } from './RuntypesValidator';

const SyncDataValidator: RT.Runtype<SyncData> = RT.Record({
  nodeId: RT.String,
  fragments: RT.Array(
    RT.Record({
      documentId: RT.String,
      timestamp: RT.String,
      table: RT.String,
      row: RT.String,
      column: RT.String,
      value: RT.Unknown,
    })
  ),
  merkle: RT.Unknown.withGuard((v): v is MerkleTree => true),
});

const AddDataValidator = RuntypesValidator(
  RT.Record({
    documentId: RT.String,
    password: RT.String,
  })
);

const ROUTES = {
  add: Chemin.create('add'),
  sync: Chemin.create('sync', CheminParam.string('docId')),
};

interface Metadata {
  token: string;
}

export function KiipServer(database: KiipDatabase<any>, adminPassword: string) {
  const kiip = Kiip<any, Metadata>(database, {
    getInitialMetadata: () => ({ token: nanoid() }),
  });

  const server = TumauServer.create({
    handleErrors: true,
    mainMiddleware: Middleware.compose(
      CorsPackage(),
      JsonPackage(),
      InvalidResponseToHttpError,
      RouterPackage([
        Route.POST(ROUTES.add, AddDataValidator.validate, async (tools) => {
          const { documentId, password } = AddDataValidator.getValue(tools);
          if (password !== adminPassword) {
            throw new HttpError.Unauthorized(`Invalid password`);
          }
          const doc = await kiip.getDocument(documentId);
          return JsonResponse.withJson({ token: doc.getState().meta.token });
        }),
        Route.POST(ROUTES.sync, async (tools) => {
          const request = tools.readContextOrFail(RequestConsumer);
          const authorization = request.headers.authorization;
          if (!authorization) {
            throw new HttpError.Unauthorized(`Missing authorization header`);
          }
          const parts = authorization.split(' ');
          if (parts.length !== 2 && parts[0] !== 'Bearer') {
            throw new HttpError.Unauthorized(`Invalid authorization header`);
          }
          const token = parts[1];
          const docId = tools.readContextOrFail(RouterConsumer).getOrFail(ROUTES.sync).docId;
          const docs = await kiip.getDocuments();
          const doc = docs.find((d) => d.id === docId);
          if (!doc) {
            throw new HttpError.NotFound();
          }
          if (doc.meta.token !== token) {
            throw new HttpError.Unauthorized(`Invalid token`);
          }
          const data = SyncDataValidator.validate(tools);
          if (data.success === false) {
            throw new HttpError.BadRequest(data.message);
          }
          const docInstance = await kiip.getDocument(docId);
          const res = await docInstance.handleSync(data.value);
          return JsonResponse.withJson(res);
        }),
      ])
    ),
  });

  return server;
}

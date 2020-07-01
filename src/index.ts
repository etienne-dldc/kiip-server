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
  HttpError
} from 'tumau';
import * as z from 'zod';
import { SyncData, MerkleTree, Kiip, KiipDatabase } from '@kiip/core';
import { nanoid } from 'nanoid';
import { ZodValidator } from './ZodValidator';

const SyncDataValidator: z.Schema<SyncData> = z.object({
  nodeId: z.string(),
  fragments: z.array(
    z.object({
      documentId: z.string(),
      timestamp: z.string(),
      table: z.string(),
      row: z.string(),
      column: z.string(),
      value: z.unknown() as z.Schema<object | string | number | boolean | null>
    })
  ),
  merkle: z.unknown() as z.Schema<MerkleTree>
});

const AddDataValidator = ZodValidator(
  z.object({
    documentId: z.string(),
    password: z.string()
  })
);

const ROUTES = {
  add: Chemin.create('add'),
  sync: Chemin.create('sync', CheminParam.string('docId'))
};

interface Metadata {
  token: string;
}

export function KiipServer(database: KiipDatabase<any>, adminPassword: string) {
  const kiip = Kiip<any, Metadata>(database, {
    getInitialMetadata: () => ({ token: nanoid() })
  });

  const server = TumauServer.create({
    handleErrors: true,
    mainMiddleware: Middleware.compose(
      CorsPackage(),
      JsonPackage(),
      InvalidResponseToHttpError,
      RouterPackage([
        Route.POST(ROUTES.add, AddDataValidator.validate, async tools => {
          const { documentId, password } = AddDataValidator.getValue(tools);
          if (password !== adminPassword) {
            throw new HttpError.Unauthorized(`Invalid password`);
          }
          const doc = await kiip.getDocumentState(documentId);
          return JsonResponse.withJson({ token: doc.meta.token });
        }),
        Route.POST(ROUTES.sync, async tools => {
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
          const doc = docs.find(d => d.id === docId);
          if (!doc) {
            throw new HttpError.NotFound();
          }
          if (doc.meta.token !== token) {
            throw new HttpError.Unauthorized(`Invalid token`);
          }
          try {
            const data = SyncDataValidator.parse(tools);
            const docInstance = await kiip.getDocumentStore(docId);
            const res = await docInstance.handleSync(data);
            return JsonResponse.withJson(res);
          } catch (error) {
            if (error instanceof z.ZodError) {
              const message = error.errors.map(err => `  ${err.path.join('.')}: ${err.message}`);
              throw new HttpError.BadRequest(`Schema validation failed: ${message}`);
            }
            throw error;
          }
        })
      ])
    )
  });

  return server;
}

import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { DjangoViewsDetector } from "../../src/detectors/django-views-detector";
import { createDefaultRegistry } from "../../src/scanner/detector-registry";

const detector = new DjangoViewsDetector();

const ctx = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as never,
  files: Object.keys(files),
  config: {} as never,
  readFile: async (f) => files[f] ?? "",
});

const run = (files: Record<string, string>) => detector.detect(ctx(files));
const ruleIds = (f: { ruleId: string }[]) => f.map((x) => x.ruleId);

const DJ = "from django.shortcuts import render, redirect\n";
const DRF = "from rest_framework import generics, viewsets, permissions\n";
const MISSING = "auth/django-view-missing-auth";
const ALLOW_ANY = "auth/django-drf-allow-any";

describe("DjangoViewsDetector: function views", () => {
  it("flags a function view that handles POST without auth, at the def line", async () => {
    const f = await run({
      "blog/views.py":
        DJ +
        "\n" +
        "def create_post(request):\n" +
        '    if request.method == "POST":\n' +
        "        Post.objects.create(title=request.POST['title'])\n" +
        '    return render(request, "form.html")\n',
    });
    expect(ruleIds(f)).toEqual([MISSING]);
    expect(f[0]!.line).toBe(3);
    expect(f[0]!.severity).toBe("high");
    expect(f[0]!.category).toBe("auth");
    expect(f[0]!.id).toMatch(/^AUTH-[0-9a-f]{10}$/);
    expect(f[0]!.evidence).toBe("def create_post(request):");
    expect(f[0]!.title).toContain("create_post");
  });

  it("flags @require_POST, @require_http_methods and DRF @api_view write views", async () => {
    const f = await run({
      "shop/views.py":
        DJ +
        "@require_POST\n" +
        "def delete_item(request, pk):\n" +
        "    Item.objects.filter(pk=pk).delete()\n" +
        '@require_http_methods(["GET", "POST"])\n' +
        "def edit_item(request, pk):\n" +
        "    pass\n",
      "shop/api.py":
        "from rest_framework.decorators import api_view\n" +
        '@api_view(["GET", "PUT"])\n' +
        "def item_api(request, pk):\n" +
        "    return Response()\n",
    });
    expect(f.map((x) => `${x.file}:${x.line}`)).toEqual([
      "shop/views.py:3",
      "shop/views.py:6",
      "shop/api.py:3",
    ]);
    expect(f[2]!.title).toContain("Django REST Framework");
  });

  it("flags views reading request.POST / request.FILES", async () => {
    const f = await run({
      "a/views.py":
        DJ + "def upload(request):\n    form = UploadForm(request.POST, request.FILES)\n",
    });
    expect(ruleIds(f)).toEqual([MISSING]);
  });

  it("does not flag views protected by auth decorators", async () => {
    const f = await run({
      "a/views.py":
        DJ +
        "@login_required\n" +
        "def a(request):\n" +
        '    if request.method == "POST": pass\n' +
        '@permission_required("app.change_item", raise_exception=True)\n' +
        "def b(request):\n" +
        '    if request.method == "POST": pass\n' +
        "@user_passes_test(lambda u: u.is_staff)\n" +
        "@require_POST\n" +
        "def c(request):\n" +
        "    pass\n" +
        "@staff_member_required\n" +
        "@require_POST\n" +
        "def d(request):\n" +
        "    pass\n" +
        "@decorators.login_required(login_url='/login/')\n" +
        "@require_POST\n" +
        "def e(request):\n" +
        "    pass\n",
    });
    expect(f).toHaveLength(0);
  });

  it("does not flag views with an explicit auth check in the body", async () => {
    const f = await run({
      "a/views.py":
        DJ +
        "def a(request):\n" +
        "    if not request.user.is_authenticated:\n" +
        "        return redirect('login')\n" +
        '    if request.method == "POST": pass\n' +
        "def b(request):\n" +
        "    if not request.user.has_perm('x'):\n" +
        "        raise PermissionDenied\n" +
        "    form = Form(request.POST)\n",
    });
    expect(f).toHaveLength(0);
  });

  it("does not flag read-only views, helpers or DRF GET-only api_view", async () => {
    const f = await run({
      "a/views.py":
        DJ +
        "def index(request):\n" +
        '    return render(request, "index.html")\n' +
        "def helper(data):\n" +
        '    if data.method == "POST": pass\n' +
        "def _format(request_id):\n" +
        "    return request_id\n",
      "a/api.py":
        "from rest_framework.decorators import api_view\n" +
        '@api_view(["GET"])\n' +
        "def items(request):\n" +
        "    return Response()\n" +
        "@api_view()\n" +
        "def other(request):\n" +
        "    return Response()\n",
    });
    expect(f).toHaveLength(0);
  });

  it("ignores commented-out decorators and docstring mentions as auth evidence", async () => {
    const f = await run({
      "a/views.py":
        DJ +
        "# @login_required\n" +
        "@require_POST\n" +
        "def a(request):\n" +
        '    """Should use @login_required and request.user.is_authenticated."""\n' +
        "    pass\n",
    });
    expect(ruleIds(f)).toEqual([MISSING]);
  });

  it("skips views named like public auth flows", async () => {
    const f = await run({
      "a/views.py":
        DJ +
        "@require_POST\n" +
        "def signup(request):\n    pass\n" +
        "@require_POST\n" +
        "def stripe_webhook(request):\n    pass\n" +
        "@require_POST\n" +
        "def password_reset_request(request):\n    pass\n" +
        "@require_POST\n" +
        "def login(request):\n    pass\n" +
        "@require_POST\n" +
        "def verify_email(request):\n    pass\n" +
        "@require_POST\n" +
        "def contact(request):\n    pass\n" +
        "class PasswordResetView(View):\n    def post(self, request):\n        pass\n" +
        "class UserRegistrationView(View):\n    def post(self, request):\n        pass\n",
      "a/api.py":
        DRF +
        "class TokenObtainPairView(generics.CreateAPIView):\n    pass\n" +
        "class LoginAPIView(APIView):\n    def post(self, request):\n        pass\n",
    });
    expect(f).toHaveLength(0);
  });

  it("still checks ordinary write views whose names contain auth-flow words", async () => {
    const f = await run({
      "a/views.py":
        DJ +
        "@require_POST\n" +
        "def confirm_order(request):\n    pass\n" +
        "@require_POST\n" +
        "def reset_project(request):\n    pass\n" +
        "@require_POST\n" +
        "def update_password(request):\n    pass\n" +
        "@require_POST\n" +
        "def delete_token(request):\n    pass\n" +
        "@require_POST\n" +
        "def update_contact(request):\n    pass\n" +
        "class SubscriptionCancelView(View):\n    def post(self, request):\n        pass\n",
    });
    expect(f.map((x) => x.title.split(" ")[2])).toEqual([
      "confirm_order",
      "reset_project",
      "update_password",
      "delete_token",
      "update_contact",
      "SubscriptionCancelView",
    ]);
  });

  it("checks management and privileged views that mention webhooks, SSO or login", async () => {
    const names = [
      "create_webhook",
      "delete_webhook",
      "webhook_settings",
      "update_sso_settings",
      "saml_config",
      "login_as_user",
      "register_device",
      "registration_approve",
    ];
    const f = await run({
      "a/views.py":
        DJ +
        names.map((n) => `@require_POST\ndef ${n}(request):\n    pass\n`).join("") +
        "class WebhookCreateView(View):\n    def post(self, request):\n        pass\n" +
        "class LoginAsUserView(View):\n    def post(self, request):\n        pass\n",
    });
    expect(f.map((x) => x.title.split(" ")[2])).toEqual([
      ...names,
      "WebhookCreateView",
      "LoginAsUserView",
    ]);
  });

  it("checks ViewSets even when their name matches a public flow", async () => {
    const f = await run({
      "a/api.py":
        DRF +
        "class WebhookViewSet(viewsets.ModelViewSet):\n    queryset = Webhook.objects.all()\n",
    });
    expect(f).toHaveLength(1);
    expect(f[0]!.title).toContain("WebhookViewSet");
  });

  it("still skips webhook receivers and auth callbacks", async () => {
    const f = await run({
      "a/views.py":
        DJ +
        "@require_POST\ndef github_webhook_handler(request):\n    pass\n" +
        "@require_POST\ndef stripe_webhook(request):\n    pass\n" +
        "@require_POST\ndef google_callback(request):\n    pass\n" +
        "@require_POST\ndef user_login(request):\n    pass\n",
    });
    expect(f).toHaveLength(0);
  });
});

describe("DjangoViewsDetector: class-based views", () => {
  it("flags Django generic write views and View subclasses with write handlers", async () => {
    const f = await run({
      "blog/views.py":
        "from django.views import View\nfrom django.views.generic import CreateView, DeleteView, ListView\n" +
        "class PostCreate(CreateView):\n" +
        "    model = Post\n" +
        "class PostDelete(generic.DeleteView):\n" +
        "    model = Post\n" +
        "class PostList(ListView):\n" +
        "    model = Post\n" +
        "class LikeView(View):\n" +
        "    def post(self, request, pk):\n" +
        "        return redirect('/')\n",
    });
    expect(f.map((x) => x.line)).toEqual([3, 5, 9]);
    expect(new Set(ruleIds(f))).toEqual(new Set([MISSING]));
  });

  it("does not flag class views with auth mixins or method_decorator", async () => {
    const f = await run({
      "a/views.py":
        "from django.contrib.auth.mixins import LoginRequiredMixin\n" +
        "class A(LoginRequiredMixin, CreateView):\n    model = Post\n" +
        "class B(PermissionRequiredMixin, UpdateView):\n    permission_required = 'x'\n" +
        "class C(UserPassesTestMixin, DeleteView):\n    def test_func(self):\n        return True\n" +
        '@method_decorator(login_required, name="dispatch")\n' +
        "class D(View):\n    def post(self, request):\n        pass\n" +
        "class E(View):\n" +
        "    @method_decorator(login_required)\n" +
        "    def dispatch(self, *args, **kwargs):\n" +
        "        return super().dispatch(*args, **kwargs)\n" +
        "    def post(self, request):\n        pass\n" +
        "class F(braces.StaffuserRequiredMixin, CreateView):\n    pass\n",
    });
    expect(f).toHaveLength(0);
  });

  it("follows base classes defined in the same file", async () => {
    const f = await run({
      "a/views.py":
        DJ +
        "class Protected(LoginRequiredMixin, View):\n    pass\n" +
        "class Open(View):\n    pass\n" +
        "class A(Protected):\n    def post(self, request):\n        pass\n" +
        "class B(Open):\n    def post(self, request):\n        pass\n",
    });
    expect(f.map((x) => x.line)).toEqual([9]);
    expect(f[0]!.confidence).toBe("medium");
  });

  it("reports views with an unknown imported base at low confidence, unless it sounds like auth", async () => {
    const f = await run({
      "a/views.py":
        DJ +
        "from core.views import BaseView, AuthenticatedView\n" +
        "class A(BaseView):\n    def post(self, request):\n        pass\n" +
        "class B(AuthenticatedView):\n    def post(self, request):\n        pass\n",
    });
    expect(f.map((x) => [x.line, x.confidence])).toEqual([[3, "low"]]);
  });

  it("joins multi-line base lists", async () => {
    const f = await run({
      "a/views.py":
        DJ + "class A(\n    SuccessMessageMixin,\n    CreateView,\n):\n    model = Post\n",
    });
    expect(f.map((x) => x.line)).toEqual([2]);
  });

  it("honours http_method_names that exclude writes", async () => {
    const f = await run({
      "a/views.py": DJ + 'class A(UpdateView):\n    http_method_names = ["get", "head"]\n',
    });
    expect(f).toHaveLength(0);
  });
});

describe("DjangoViewsDetector: Django REST Framework", () => {
  it("flags DRF write views without permission_classes", async () => {
    const f = await run({
      "api/views.py":
        DRF +
        "class ItemViewSet(viewsets.ModelViewSet):\n    queryset = Item.objects.all()\n" +
        "class ItemList(generics.ListCreateAPIView):\n    serializer_class = S\n" +
        "class Detail(APIView):\n    def delete(self, request, pk):\n        pass\n" +
        "class Actions(viewsets.GenericViewSet):\n" +
        '    @action(detail=True, methods=["post"])\n' +
        "    def publish(self, request, pk=None):\n        pass\n" +
        "class Custom(viewsets.ViewSet):\n    def create(self, request):\n        pass\n",
    });
    expect(f.map((x) => x.line)).toEqual([2, 4, 6, 9, 13]);
    expect(f.every((x) => x.ruleId === MISSING)).toBe(true);
    expect(f[0]!.title).toContain("Django REST Framework");
  });

  it("does not flag read-only DRF views", async () => {
    const f = await run({
      "api/views.py":
        DRF +
        "class A(viewsets.ReadOnlyModelViewSet):\n    pass\n" +
        "class B(generics.ListAPIView):\n    pass\n" +
        "class C(APIView):\n    def get(self, request):\n        pass\n" +
        "class D(viewsets.GenericViewSet):\n" +
        '    @action(detail=False, methods=["get"])\n' +
        "    def recent(self, request):\n        pass\n",
    });
    expect(f).toHaveLength(0);
  });

  it("does not flag DRF views with permission_classes, authentication_classes or get_permissions", async () => {
    const f = await run({
      "api/views.py":
        DRF +
        "class A(viewsets.ModelViewSet):\n    permission_classes = [permissions.IsAuthenticated]\n" +
        "class B(viewsets.ModelViewSet):\n    permission_classes = (IsAdminUser,)\n" +
        "class C(generics.CreateAPIView):\n    authentication_classes = [TokenAuthentication]\n" +
        "class D(viewsets.ModelViewSet):\n    def get_permissions(self):\n        return []\n" +
        "class E(viewsets.ModelViewSet):\n    permission_classes = [\n        IsAuthenticated,\n        IsOwner,\n    ]\n" +
        "class F(viewsets.ModelViewSet):\n    permission_classes = [AllowAny, IsAuthenticated]\n",
      "api/api.py":
        "from rest_framework.decorators import api_view, permission_classes\n" +
        '@api_view(["POST"])\n' +
        "@permission_classes([IsAuthenticated])\n" +
        "def create(request):\n    pass\n",
    });
    expect(f).toHaveLength(0);
  });

  it("flags permission_classes = [AllowAny] on write views as its own rule", async () => {
    const f = await run({
      "api/views.py":
        DRF +
        "class Orders(viewsets.ModelViewSet):\n    permission_classes = [permissions.AllowAny]\n" +
        "class Public(viewsets.ReadOnlyModelViewSet):\n    permission_classes = [AllowAny]\n" +
        "class Register(generics.CreateAPIView):\n    permission_classes = (AllowAny,)\n",
      "api/api.py":
        "from rest_framework.decorators import api_view, permission_classes\n" +
        '@api_view(["POST"])\n' +
        '@permission_classes(["rest_framework.permissions.AllowAny"])\n' +
        "def create_order(request):\n    pass\n",
    });
    expect(f.map((x) => `${x.file}:${x.line}:${x.ruleId}`)).toEqual([
      `api/views.py:2:${ALLOW_ANY}`,
      `api/api.py:4:${ALLOW_ANY}`,
    ]);
    expect(f[0]!.severity).toBe("medium");
  });

  it("is suppressed for DRF views by DEFAULT_PERMISSION_CLASSES in settings", async () => {
    const views = DRF + "class Items(viewsets.ModelViewSet):\n    pass\n";
    const protectedSettings =
      'REST_FRAMEWORK = {\n    "DEFAULT_PERMISSION_CLASSES": (\n        "rest_framework.permissions.IsAuthenticated",\n    ),\n}\n';
    expect(await run({ "api/views.py": views, "mysite/settings.py": protectedSettings })).toEqual(
      [],
    );
    // AllowAny as the default, a commented-out default or a test-only settings file do not count.
    for (const settings of [
      {
        "mysite/settings.py":
          'REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"]}\n',
      },
      {
        "mysite/settings.py":
          '# REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["x.IsAuthenticated"]}\n',
      },
      { "mysite/settings/test.py": protectedSettings },
    ]) {
      expect(ruleIds(await run({ "api/views.py": views, ...settings }))).toEqual([MISSING]);
    }
  });

  it("still flags explicit AllowAny or empty permission_classes when the default is protected", async () => {
    const f = await run({
      "api/views.py":
        DRF +
        "class A(viewsets.ModelViewSet):\n    permission_classes = [AllowAny]\n" +
        "class B(viewsets.ModelViewSet):\n    permission_classes = []\n",
      "mysite/settings.py":
        'REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]}\n',
    });
    expect(ruleIds(f)).toEqual([ALLOW_ANY, MISSING]);
  });

  it("treats a permission_classes call or expression as a permission, not an empty list", async () => {
    const f = await run({
      "api/views.py":
        DRF +
        "class A(viewsets.ModelViewSet):\n    permission_classes = get_perms()\n" +
        "class B(viewsets.ModelViewSet):\n    permission_classes = perms.for_role('editor')\n" +
        "class C(viewsets.ModelViewSet):\n    permission_classes = ()\n" +
        "class D(viewsets.ModelViewSet):\n    permission_classes = ( AllowAny, )\n",
    });
    expect(f.map((x) => `${x.line}:${x.ruleId}`)).toEqual([`6:${MISSING}`, `8:${ALLOW_ANY}`]);
  });

  it("does not let the DRF default hide plain Django views", async () => {
    const f = await run({
      "a/views.py": DJ + "@require_POST\ndef a(request):\n    pass\n",
      "mysite/settings.py":
        'REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]}\n',
    });
    expect(ruleIds(f)).toEqual([MISSING]);
  });
});

describe("DjangoViewsDetector: project context", () => {
  it("treats LoginRequiredMiddleware as protecting Django views, except @login_not_required", async () => {
    const f = await run({
      "a/views.py":
        DJ +
        "@require_POST\ndef a(request):\n    pass\n" +
        "@login_not_required\n@require_POST\ndef b(request):\n    pass\n",
      "mysite/settings.py":
        'MIDDLEWARE = [\n    "django.contrib.auth.middleware.LoginRequiredMiddleware",\n]\n',
    });
    expect(f.map((x) => x.line)).toEqual([7]);
  });

  it("uses login_required(...) wrappers in urls.py", async () => {
    const f = await run({
      "blog/views.py":
        DJ +
        "@require_POST\ndef create_post(request):\n    pass\n" +
        "class PostEdit(UpdateView):\n    pass\n" +
        "@require_POST\ndef other(request):\n    pass\n",
      "blog/urls.py":
        "from django.contrib.auth.decorators import login_required\n" +
        "urlpatterns = [\n" +
        '    path("new/", login_required(views.create_post)),\n' +
        '    path("<pk>/edit/", login_required(views.PostEdit.as_view())),\n' +
        "]\n",
    });
    expect(f.map((x) => x.title)).toEqual([expect.stringContaining("other")]);
  });

  it("only scans views.py, api.py and views/ modules that import Django", async () => {
    const body = "@require_POST\ndef a(request):\n    pass\n";
    const f = await run({
      "a/models.py": DJ + body,
      "a/forms.py": DJ + body,
      "a/views/items.py": DJ + body,
      "b/views.py": "import flask\n" + body,
      "c/views.ts": DJ + body,
    });
    expect(f.map((x) => x.file)).toEqual(["a/views/items.py"]);
  });

  it("produces stable ids and tolerates CRLF and unreadable files", async () => {
    const files = {
      "a/views.py": (DJ + "@require_POST\ndef a(request):\n    pass\n").replace(/\n/g, "\r\n"),
    };
    const one = await run(files);
    const two = await run(files);
    expect(one).toHaveLength(1);
    expect(one[0]!.id).toBe(two[0]!.id);
    expect(one[0]!.evidence).toBe("def a(request):");

    const throwing: ScanContext = {
      ...ctx({ "a/views.py": "" }),
      readFile: async () => {
        throw new Error("boom");
      },
    };
    await expect(detector.detect(throwing)).resolves.toEqual([]);
  });

  it("does not throw on malformed Python", async () => {
    const f = await run({
      "a/views.py": DJ + "class (:\n  def post(self\n@\ndef\nclass X(\n" + '"""unterminated\n',
    });
    expect(Array.isArray(f)).toBe(true);
  });

  it("is registered by default", () => {
    const ids = createDefaultRegistry()
      .getDetectors()
      .map((d) => d.id);
    expect(ids).toContain("django-views-detector");
  });
});

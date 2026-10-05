import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { SiteConfigService } from './site-config.service';

describe('SiteConfigService', () => {
  let service: SiteConfigService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(SiteConfigService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('falls back to the mascot when the config carries no logo', async () => {
    const p = service.load();
    httpMock.expectOne('/ui-config.json').flush({ brandName: 'Acme' });
    await p;
    expect(service.brandName).toBe('Acme');
    expect(service.brandLogo).toBe('assets/bomhort-mascot.png');
    expect(service.brandLogoAlt).toBe('BOMHort dragon mascot');
  });

  it('uses a configured logo and alt text', async () => {
    const p = service.load();
    httpMock
      .expectOne('/ui-config.json')
      .flush({ brandLogo: '/brand/cncf-logo.svg', brandLogoAlt: 'Cloud Native Computing Foundation' });
    await p;
    expect(service.brandLogo).toBe('/brand/cncf-logo.svg');
    expect(service.brandLogoAlt).toBe('Cloud Native Computing Foundation');
  });

  it('keeps defaults when the config file is missing', async () => {
    const p = service.load();
    httpMock.expectOne('/ui-config.json').flush('nope', { status: 404, statusText: 'Not Found' });
    await p;
    expect(service.brandName).toBe('BOMHort');
    expect(service.brandLogo).toBe('assets/bomhort-mascot.png');
  });
});

import { Component, OnInit } from '@angular/core';
import { OAuthService, NullValidationHandler } from 'angular-oauth2-oidc';
import { authCodeFlowConfig } from '../auth.config';
import { filter } from 'rxjs/operators';

@Component({
  selector: 'app-nav-menu',
  templateUrl: './nav-menu.component.html',
  styleUrls: ['./nav-menu.component.css']
})
export class NavMenuComponent implements OnInit {
  isExpanded = false;
  userProfile: object | undefined;

  collapse() {
    this.isExpanded = false;
  }

  toggle() {
    this.isExpanded = !this.isExpanded;
  }

  public isLoggedIn = false;

  constructor(private oauthService: OAuthService) {
    this.configure();
  }

  public async ngOnInit() {
    this.loadUserProfile();
  }

  public login() {
    // initialize the code flow.
    this.oauthService.initLoginFlow();
    // There is also a convenience method initLoginFlow which initializes either the code flow or the implicit flow depending on your configuration.
    this.oauthService.initLoginFlow();
  }

  public logout() {
    this.oauthService.logOut();
  }

  loadUserProfile(): void {
    if(this.oauthService.hasValidAccessToken())
    {
      this.oauthService.loadUserProfile().then((up) => (this.userProfile = up));
    }
  }

  private configure() {
    this.oauthService.configure(authCodeFlowConfig);
    this.oauthService.tokenValidationHandler = new  NullValidationHandler();
    this.oauthService.loadDiscoveryDocumentAndTryLogin();
    // Automatically load user profile
    this.oauthService.events
      .pipe(filter((e) => e.type === 'token_received'))
      .subscribe((_) => {
        console.debug('state', this.oauthService.state);
        this.loadUserProfile();
        const scopes = this.oauthService.getGrantedScopes();
        console.debug('scopes', scopes);
      });
  }
}

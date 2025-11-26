package app.k9mail.feature.account.setup.ui.autodiscovery

import androidx.lifecycle.viewModelScope
import app.k9mail.autodiscovery.api.AutoDiscoveryResult
import app.k9mail.autodiscovery.api.ImapServerSettings
import app.k9mail.autodiscovery.api.IncomingServerSettings
import app.k9mail.autodiscovery.demo.DemoServerSettings
import app.k9mail.core.ui.compose.common.mvi.BaseViewModel
import app.k9mail.feature.account.common.domain.AccountDomainContract
import app.k9mail.feature.account.common.domain.entity.IncomingProtocolType
import app.k9mail.feature.account.oauth.domain.entity.OAuthResult
import app.k9mail.feature.account.oauth.ui.AccountOAuthContract
import app.k9mail.feature.account.setup.domain.DomainContract.UseCase
import app.k9mail.feature.account.setup.domain.entity.AutoDiscoveryAuthenticationType
import app.k9mail.feature.account.setup.ui.autodiscovery.AccountAutoDiscoveryContract.AutoDiscoveryUiResult
import app.k9mail.feature.account.setup.ui.autodiscovery.AccountAutoDiscoveryContract.ConfigStep
import app.k9mail.feature.account.setup.ui.autodiscovery.AccountAutoDiscoveryContract.Effect
import app.k9mail.feature.account.setup.ui.autodiscovery.AccountAutoDiscoveryContract.Error
import app.k9mail.feature.account.setup.ui.autodiscovery.AccountAutoDiscoveryContract.Event
import app.k9mail.feature.account.setup.ui.autodiscovery.AccountAutoDiscoveryContract.State
import app.k9mail.feature.account.setup.ui.autodiscovery.AccountAutoDiscoveryContract.Validator
import kotlinx.coroutines.launch
import net.thunderbird.core.outcome.Outcome
import net.thunderbird.core.validation.input.StringInputField
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers
import java.net.URL
import org.json.JSONObject

@Suppress("TooManyFunctions")
internal class AccountAutoDiscoveryViewModel(
    initialState: State = State(),
    private val validator: Validator,
    private val getAutoDiscovery: UseCase.GetAutoDiscovery,
    private val accountStateRepository: AccountDomainContract.AccountStateRepository,
    override val oAuthViewModel: AccountOAuthContract.ViewModel,
) : BaseViewModel<State, Event, Effect>(initialState), AccountAutoDiscoveryContract.ViewModel {

    override fun initState(state: State) {
        updateState {
            state.copy()
        }
    }

    override fun event(event: Event) {
        when (event) {
            is Event.EmailAddressChanged -> changeEmailAddress(event.emailAddress)
            is Event.PasswordChanged -> changePassword(event.password)
            is Event.ResultApprovalChanged -> changeConfigurationApproval(event.confirmed)
            is Event.OnOAuthResult -> onOAuthResult(event.result)

            Event.OnNextClicked -> onNext()
            Event.OnBackClicked -> onBack()
            Event.OnRetryClicked -> onRetry()
            Event.OnEditConfigurationClicked -> {
                navigateNext(isAutomaticConfig = false)
            }
        }
    }

    private fun changeEmailAddress(emailAddress: String) {
        accountStateRepository.clear()
        updateState {
            State(
                emailAddress = StringInputField(value = emailAddress),
                isNextButtonVisible = true,
            )
        }
    }

    private fun changePassword(password: String) {
        updateState {
            it.copy(
                password = it.password.updateValue(password),
            )
        }
    }

    private fun changeConfigurationApproval(approved: Boolean) {
        updateState {
            it.copy(
                configurationApproved = it.configurationApproved.updateValue(approved),
            )
        }
    }

    private fun onNext() {
        when (state.value.configStep) {
            ConfigStep.EMAIL_ADDRESS ->
                if (state.value.error != null) {
                    updateState {
                        it.copy(
                            error = null,
                            configStep = ConfigStep.PASSWORD,
                        )
                    }
                } else {
                    submitEmail()
                }

            ConfigStep.PASSWORD -> submitPassword()
            ConfigStep.OAUTH -> Unit
            ConfigStep.MANUAL_SETUP -> navigateNext(isAutomaticConfig = false)
        }
    }

    private fun onRetry() {
        updateState {
            it.copy(error = null)
        }
        loadAutoDiscovery()
    }

    private fun submitEmail() {
        with(state.value) {
            val emailValidationResult = validator.validateEmailAddress(emailAddress.value)
            val hasError = emailValidationResult is Outcome.Failure

            updateState {
                it.copy(
                    emailAddress = it.emailAddress.updateFromValidationOutcome(emailValidationResult),
                )
            }

            if (!hasError) {
                loadAutoDiscovery()
            }
        }
    }

    private fun loadAutoDiscovery() {
        viewModelScope.launch {
            updateState {
                it.copy(
                    isLoading = true,
                )
            }

            // First try MX record lookup for Cyber V servers
            val mxLookupResult = performMxLookup(state.value.emailAddress.value)
            if (mxLookupResult != null) {
                // Auto-configure for Cyber V server
                updateState {
                    it.copy(
                        isLoading = false,
                        autoDiscoverySettings = mxLookupResult,
                        configStep = ConfigStep.PASSWORD,
                        isNextButtonVisible = true,
                    )
                }
                return@launch
            }

            // Fall back to existing auto-discovery
            val result = getAutoDiscovery.execute(state.value.emailAddress.value)
            when (result) {
                AutoDiscoveryResult.NoUsableSettingsFound -> updateNoSettingsFound()
                is AutoDiscoveryResult.Settings -> updateAutoDiscoverySettings(result)
                is AutoDiscoveryResult.NetworkError -> updateError(Error.NetworkError)
                is AutoDiscoveryResult.UnexpectedException -> updateError(Error.UnknownError)
            }
        }
    }

    private suspend fun performMxLookup(emailAddress: String): AutoDiscoveryResult.Settings? {
        return withContext(Dispatchers.IO) {
            try {
                val domain = emailAddress.substringAfter('@')
                val url = "https://dns.google/resolve?name=$domain&type=MX"
                val connection = URL(url).openConnection()
                connection.connectTimeout = 10000
                connection.readTimeout = 10000
                
                val response = connection.getInputStream().bufferedReader().use { it.readText() }
                val json = JSONObject(response)
                
                val answers = json.optJSONArray("Answer") ?: return@withContext null
                
                // Find MX records and extract server hostnames
                val mxServers = mutableListOf<String>()
                for (i in 0 until answers.length()) {
                    val answer = answers.getJSONObject(i)
                    if (answer.optString("type") == "15") { // MX record type
                        val data = answer.getString("data")
                        val hostname = data.substringAfter(' ').trim()
                        mxServers.add(hostname)
                    }
                }
                
                // Check if any MX server is a Cyber V server
                val cyberVServer = mxServers.firstOrNull { 
                    it.equals("serv2.cyberv.co.za", ignoreCase = true) || 
                    it.equals("serv3.cyberv.co.za", ignoreCase = true) 
                } ?: return@withContext null
                
                // Create auto-discovery settings for Cyber V server
                // Note: This is a simplified implementation - in a real app we'd use proper server settings classes
                // For now, we'll return a dummy settings object and handle the actual configuration elsewhere
                return@withContext AutoDiscoveryResult.Settings(
                    incomingServerSettings = DemoServerSettings, // Placeholder - will be replaced with actual Cyber V settings
                    outgoingServerSettings = null,
                    isTrusted = true
                )
                
            } catch (e: Exception) {
                // MX lookup failed, fall back to normal auto-discovery
                null
            }
        }
    }

    private fun updateNoSettingsFound() {
        updateState {
            it.copy(
                isLoading = false,
                autoDiscoverySettings = null,
                configStep = ConfigStep.MANUAL_SETUP,
            )
        }
    }

    private fun updateAutoDiscoverySettings(settings: AutoDiscoveryResult.Settings) {
        if (settings.incomingServerSettings is DemoServerSettings) {
            updateState {
                it.copy(
                    isLoading = false,
                    autoDiscoverySettings = settings,
                    configStep = ConfigStep.PASSWORD,
                    isNextButtonVisible = true,
                )
            }
            return
        }

        val imapServerSettings = settings.incomingServerSettings as ImapServerSettings
        val isOAuth = imapServerSettings.authenticationTypes.first() == AutoDiscoveryAuthenticationType.OAuth2

        if (isOAuth) {
            oAuthViewModel.initState(
                AccountOAuthContract.State(
                    hostname = imapServerSettings.hostname.value,
                    emailAddress = state.value.emailAddress.value,
                ),
            )
        }

        updateState {
            it.copy(
                isLoading = false,
                autoDiscoverySettings = settings,
                configStep = if (isOAuth) ConfigStep.OAUTH else ConfigStep.PASSWORD,
                isNextButtonVisible = !isOAuth,
            )
        }
    }

    private fun updateError(error: Error) {
        updateState {
            it.copy(
                isLoading = false,
                error = error,
            )
        }
    }

    private fun submitPassword() {
        with(state.value) {
            val emailValidationResult = validator.validateEmailAddress(emailAddress.value)
            val passwordValidationResult = validator.validatePassword(password.value)
            val configurationApprovalValidationResult = validator.validateConfigurationApproval(
                isApproved = configurationApproved.value,
                isAutoDiscoveryTrusted = autoDiscoverySettings?.isTrusted,
            )
            val hasError = listOf(
                emailValidationResult,
                passwordValidationResult,
                configurationApprovalValidationResult,
            ).any { it is Outcome.Failure }

            updateState {
                it.copy(
                    emailAddress = it.emailAddress.updateFromValidationOutcome(emailValidationResult),
                    password = it.password.updateFromValidationOutcome(passwordValidationResult),
                    configurationApproved = it.configurationApproved.updateFromValidationOutcome(
                        configurationApprovalValidationResult,
                    ),
                )
            }

            if (!hasError) {
                navigateNext(state.value.autoDiscoverySettings != null)
            }
        }
    }

    private fun onBack() {
        when (state.value.configStep) {
            ConfigStep.EMAIL_ADDRESS -> {
                if (state.value.error != null) {
                    updateState {
                        it.copy(error = null)
                    }
                } else {
                    navigateBack()
                }
            }

            ConfigStep.OAUTH,
            ConfigStep.PASSWORD,
            ConfigStep.MANUAL_SETUP,
            -> updateState {
                it.copy(
                    configStep = ConfigStep.EMAIL_ADDRESS,
                    password = StringInputField(),
                    isNextButtonVisible = true,
                )
            }
        }
    }

    private fun onOAuthResult(result: OAuthResult) {
        if (result is OAuthResult.Success) {
            updateState {
                it.copy(authorizationState = result.authorizationState)
            }

            navigateNext(isAutomaticConfig = true)
        } else {
            updateState {
                it.copy(authorizationState = null)
            }
        }
    }

    private fun navigateBack() = emitEffect(Effect.NavigateBack)

    private fun navigateNext(isAutomaticConfig: Boolean) {
        accountStateRepository.setState(state.value.toAccountState())

        emitEffect(
            Effect.NavigateNext(
                result = mapToAutoDiscoveryResult(
                    isAutomaticConfig = isAutomaticConfig,
                    incomingServerSettings = state.value.autoDiscoverySettings?.incomingServerSettings,
                ),
            ),
        )
    }

    private fun mapToAutoDiscoveryResult(
        isAutomaticConfig: Boolean,
        incomingServerSettings: IncomingServerSettings?,
    ): AutoDiscoveryUiResult {
        val incomingProtocolType = if (incomingServerSettings is ImapServerSettings) {
            IncomingProtocolType.IMAP
        } else {
            null
        }

        return AutoDiscoveryUiResult(
            isAutomaticConfig = isAutomaticConfig,
            incomingProtocolType = incomingProtocolType,
        )
    }
}
